"""
ProxyForce — network inspection and route enforcement (the OS-networking seam).

WHY THIS EXISTS (v3.0.0):
  core/singbox_controller asks the operating system a fixed set of questions —
  is the TUN up, did the capture routes land, is DNS reaching fakeip, does the OS
  itself believe it has internet, who else is filtering packets — and takes one
  narrow corrective action (re-assert the capture routes). On Windows those are
  PowerShell one-liners; on Linux they are iproute2, ss and nft. The QUESTIONS are
  the same, so they live here once and each platform answers them its own way.

  Everything here is READ-ONLY except enforce_capture_routes() and
  cleanup_stale_tun(), and both only touch state that belongs to ProxyForce's own
  TUN and disappears when it is torn down.

THE ONE GENUINE DIFFERENCE — HOW THE TUN WINS THE ROUTE:
  Windows picks a route by longest-prefix-match and breaks a tie on interface
  metric. sing-box's auto_route installs 0.0.0.0/0 on the TUN, which TIES the
  physical NIC's own default and then LOSES the metric tiebreak — the root cause
  of the Win 10 "green but no capture" failure. The fix is the split-default pair
  0.0.0.0/1 + 128.0.0.0/1, which is strictly more specific than any /0.

  Linux does not have that fight: sing-box's auto_route uses POLICY routing (an
  `ip rule` selecting a dedicated table), which is consulted before the main table
  regardless of any metric. The split pair is still what ProxyForce's config asks
  for via `route_address`, and sing-box installs it into that table, so the same
  "2 of 2 prefixes present" check remains meaningful and is what
  capture_route_count() reports on both platforms — it just looks in `ip route
  show table all` rather than at one interface's route set.

  Consequence worth knowing: on Linux the repair path in enforce_capture_routes()
  is far less likely to be needed. It is kept because a box where another agent
  owns policy routing can still end up with the prefixes missing, and re-asserting
  them into the main table is the same safe, non-persistent action it is on
  Windows.
"""

import os
import re
import socket

from core import hostos

# The sing-box TUN's interface name, and the split-default pair that must be
# present for capture to be universal. Imported by singbox_controller too.
SPLIT_PREFIXES = ("0.0.0.0/1", "128.0.0.0/1")


# ══════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════

def ps(command: str, timeout: int = 20) -> str:
    """Run a PowerShell one-liner; combined stdout+stderr. Windows only — callers
    on Linux never reach a code path that uses it."""
    return hostos.run_text(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        timeout=timeout)


def _ip(*args, timeout: int = 10) -> str:
    return hostos.run_text(["ip", *args], timeout=timeout)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# host / OS
# ══════════════════════════════════════════════════════════════════════════════

def os_info() -> str:
    if hostos.IS_WINDOWS:
        return ps("(Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + "
                  "(Get-CimInstance Win32_OperatingSystem).BuildNumber")
    pretty = ""
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
            break
    kernel = hostos.run_text(["uname", "-sr"], timeout=5)
    return ("%s (kernel %s)" % (pretty or "Linux", kernel)).strip()


def tun_supported() -> "tuple[bool, str]":
    """Can this host create the TUN at all? Answering before launch turns a
    cryptic sing-box exit into a sentence the user can act on."""
    if hostos.IS_WINDOWS:
        return (True, "")
    if not os.path.exists("/dev/net/tun"):
        return (False, "/dev/net/tun is missing — load the module with "
                       "`sudo modprobe tun`, or (in a container) run with "
                       "--device /dev/net/tun --cap-add NET_ADMIN.")
    if not hostos.which("ip"):
        return (False, "the `ip` command (iproute2) is not installed — ProxyForce "
                       "needs it to manage the TUN's routes.")
    return (True, "")


# ══════════════════════════════════════════════════════════════════════════════
# TUN adapter
# ══════════════════════════════════════════════════════════════════════════════

def tun_exists(name: str) -> bool:
    """True if a network interface called `name` currently exists."""
    if hostos.IS_WINDOWS:
        try:
            r = hostos.run(["netsh", "interface", "show", "interface"], timeout=5)
            return name in (r.stdout or "")
        except Exception:
            return False
    return os.path.isdir("/sys/class/net/%s" % name)


def tun_index(name: str) -> str:
    """The interface index as a decimal string, or '' if the interface is absent."""
    if hostos.IS_WINDOWS:
        raw = ps("$a=Get-NetAdapter -Name '" + name + "' -ErrorAction SilentlyContinue; "
                 "if($a){$a.ifIndex}else{''}").strip()
        return raw if raw.isdigit() else ""
    idx = _read("/sys/class/net/%s/ifindex" % name)
    return idx if idx.isdigit() else ""


def tun_details(name: str) -> str:
    if hostos.IS_WINDOWS:
        return ps("Get-NetAdapter -Name '" + name + "' -ErrorAction SilentlyContinue | "
                  "Select-Object Name,ifIndex,Status,InterfaceDescription | "
                  "Format-List | Out-String")
    return _ip("-details", "link", "show", name)


def tun_addresses(name: str) -> str:
    if hostos.IS_WINDOWS:
        return ps("Get-NetIPAddress -InterfaceAlias '" + name + "' "
                  "-ErrorAction SilentlyContinue | Select-Object "
                  "IPAddress,PrefixLength,AddressFamily | Format-Table -Auto | Out-String")
    return _ip("-4", "addr", "show", name)


def cleanup_stale_tun(name: str) -> None:
    """Release a leftover TUN so the next launch can recreate it.

    A killed sing-box gets no chance to remove its own interface. On Windows the
    wintun device can linger with no owning process (the documented Win 10 timing
    bug); on Linux the kernel normally destroys a tun device the moment its last
    file descriptor closes, so this is a belt-and-braces path there — it matters
    only when an orphaned sing-box is still holding the fd, which killing it fixes.
    """
    kill_image("sing-box" + hostos.EXE_SUFFIX)
    if not hostos.IS_WINDOWS:
        if tun_exists(name):
            _ip("link", "delete", name)
        return
    # Best-effort device removal in case the adapter lingers with no owning
    # process: try the NetAdapter API, then fall back to pnputil removing the
    # underlying PnP device by instance id — this covers wintun adapters that
    # Remove-NetAdapter can't drop in some Windows-10 states.
    ps("$ErrorActionPreference='SilentlyContinue';"
       "$a = Get-NetAdapter -Name '" + name + "';"
       "if ($a) {"
       " Disable-NetAdapter -Name $a.Name -Confirm:$false;"
       " Remove-NetAdapter  -Name $a.Name -Confirm:$false;"
       " $b = Get-NetAdapter -Name '" + name + "';"
       " if ($b -and $b.PnpDeviceID) { pnputil /remove-device \"$($b.PnpDeviceID)\" }"
       "}", timeout=25)


def kill_image(image: str) -> None:
    """Kill every process running `image`, by name. Used to clear an orphaned
    sing-box that still owns the TUN."""
    if hostos.IS_WINDOWS:
        try:
            hostos.run(["taskkill", "/F", "/IM", image], timeout=10)
        except Exception:
            pass
        return
    try:
        hostos.run(["pkill", "-9", "-x", image], timeout=10)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# capture routes
# ══════════════════════════════════════════════════════════════════════════════

def capture_route_count(name: str, idx: str = "") -> int:
    """How many of SPLIT_PREFIXES are currently routed via the TUN (0, 1 or 2).

    Windows: routes attached to the TUN's interface index.
    Linux: any routing table, because sing-box's auto_route puts them in its own
    policy-routing table rather than the main one — see the module docstring.
    """
    if hostos.IS_WINDOWS:
        idx = idx or tun_index(name)
        if not idx:
            return 0
        out = ps("(Get-NetRoute -InterfaceIndex " + idx + " -ErrorAction SilentlyContinue | "
                 "Where-Object {$_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1'} | "
                 "Measure-Object).Count").strip()
        tail = out.splitlines()[-1].strip() if out else ""
        return int(tail) if tail.isdigit() else 0
    table = _ip("route", "show", "table", "all")
    # `dev <name>` must match the WHOLE field. A plain substring test counts
    # "dev ProxyForceOld" — a stale interface from an earlier run, or an unrelated
    # tunnel whose name merely starts the same way — as ours, and reports capture
    # as healthy while every packet leaves through the other interface.
    dev_re = re.compile(r"\bdev\s+%s(\s|$)" % re.escape(name))
    found = 0
    for prefix in SPLIT_PREFIXES:
        for line in table.splitlines():
            if line.startswith(prefix + " ") and dev_re.search(line):
                found += 1
                break
    return found


def route_table(name: str = "") -> str:
    """The routing state a human would need to see to judge capture."""
    if hostos.IS_WINDOWS:
        return ps("Get-NetRoute -AddressFamily IPv4 | Sort-Object "
                  "DestinationPrefix,RouteMetric | Select-Object -First 40 "
                  "ifIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric | "
                  "Format-Table -Auto | Out-String")
    return ("--- ip rule ---\n%s\n\n--- ip route show table all ---\n%s"
            % (_ip("rule", "show"), _ip("route", "show", "table", "all")))


def default_gateway(exclude_dev: str = "") -> "tuple[str, str]":
    """(gateway_ip, device) of the physical default route — the one the proxy's
    /32 host route must point at so sing-box's own upstream connection escapes the
    tunnel instead of looping back into it. ('', '') if there is none."""
    if hostos.IS_WINDOWS:
        out = ps(
            "$gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
            " Where-Object {$_.InterfaceAlias -ne '" + exclude_dev + "' -and $_.NextHop -and "
            "$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric |"
            " Select-Object -First 1; if($gw){\"$($gw.NextHop) $($gw.ifIndex)\"}else{''}")
        parts = out.strip().split()
        return (parts[0], parts[1]) if len(parts) == 2 else ("", "")
    for line in _ip("route", "show", "default").splitlines():
        m = re.search(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", line)
        if m and m.group(2) != exclude_dev:
            return (m.group(1), m.group(2))
    return ("", "")


def enforce_capture_routes(name: str, proxy_ip: str = "") -> "tuple[int, str]":
    """Guarantee the TUN wins the default route. Returns (count_present, note).

    Idempotent — only adds a prefix that is missing; always re-pins the metric on
    Windows. Non-persistent on both platforms (ActiveStore / the live table), so
    sing-box's teardown on stop removes everything this adds.

    `proxy_ip` is the corporate proxy's IPv4 literal, when there is one. It gets a
    /32 host route via the REAL default gateway: a /32 beats a /1, so sing-box's
    own connection to the proxy escapes the tunnel while everything else stays
    captured. Without it, that connection matches 128.0.0.0/1, is routed back into
    the TUN, and surfaces as "dial tcp <proxy>:<port>: i/o timeout".
    """
    idx = tun_index(name)
    if not idx:
        return (0, "TUN interface not found yet")

    gw_ip, gw_dev = default_gateway(exclude_dev=name) if proxy_ip else ("", "")

    if hostos.IS_WINDOWS:
        excl = ""
        if proxy_ip and gw_ip and gw_dev:
            excl = (
                "Remove-NetRoute -DestinationPrefix '" + proxy_ip + "/32' -Confirm:$false "
                "-ErrorAction SilentlyContinue;"
                "New-NetRoute -DestinationPrefix '" + proxy_ip + "/32' -InterfaceIndex "
                + gw_dev + " -NextHop " + gw_ip + " -RouteMetric 1 "
                "-PolicyStore ActiveStore | Out-Null;")
        ps("$ErrorActionPreference='SilentlyContinue';"
           + excl +
           "Set-NetIPInterface -InterfaceIndex " + idx + " -InterfaceMetric 1;"
           "foreach($p in '0.0.0.0/1','128.0.0.0/1'){"
           " if(-not (Get-NetRoute -InterfaceIndex " + idx + " -DestinationPrefix $p "
           "-ErrorAction SilentlyContinue)){"
           "  New-NetRoute -DestinationPrefix $p -InterfaceIndex " + idx +
           " -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null}};",
           timeout=25)
    else:
        if proxy_ip and gw_ip and gw_dev:
            # `replace` rather than add: idempotent, and it also corrects a stale
            # /32 left by a previous run that used a different gateway.
            _ip("route", "replace", proxy_ip + "/32", "via", gw_ip, "dev", gw_dev)
        # sing-box's auto_route normally has these in its own policy table already;
        # capture_route_count() looks across all tables, so this only fires when
        # they are genuinely absent.
        if capture_route_count(name) < 2:
            for prefix in SPLIT_PREFIXES:
                _ip("route", "replace", prefix, "dev", name, "metric", "1")

    count = capture_route_count(name, idx)
    note = ""
    if proxy_ip:
        note = (" proxy %s pinned to %s via %s (loop-break);" % (proxy_ip, gw_dev, gw_ip)
                if gw_ip and gw_dev
                else " proxy %s NOT pinned (no physical default gateway found);" % proxy_ip)
    return (count, note)


# ══════════════════════════════════════════════════════════════════════════════
# DNS
# ══════════════════════════════════════════════════════════════════════════════

def dns_a_lookup(host: str) -> str:
    """Resolve `host`'s A record the way the OS resolver would, as printable text.
    The caller checks whether the answer is in the fakeip range, which is what
    proves DNS is being intercepted by the TUN rather than going out directly."""
    if hostos.IS_WINDOWS:
        return ps("ipconfig /flushdns | Out-Null; (Resolve-DnsName -Name " + host +
                  " -Type A -ErrorAction SilentlyContinue).IPAddress -join ', '")
    if hostos.which("resolvectl"):
        out = hostos.run_text(["resolvectl", "query", "--legend=no", "-4", host])
        if out and not out.startswith("<"):
            return out
    return hostos.run_text(["getent", "ahostsv4", host])


def getaddrinfo_unspec(host: str) -> str:
    """What an application ACTUALLY calls — AF_UNSPEC, both families — rather than
    an A-only query. A box that answers A from fakeip but still returns a real AAAA
    will have dual-stack apps leaving over IPv6, around the proxy entirely."""
    if hostos.IS_WINDOWS:
        return ps("try { [System.Net.Dns]::GetHostAddresses('" + host + "') | "
                  "ForEach-Object { $_.AddressFamily.ToString() + ' ' + "
                  "$_.IPAddressToString } } catch { 'lookup failed: ' + $_.Exception.Message }")
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception as e:
        return "lookup failed: %s" % e
    seen, lines = set(), []
    for family, _t, _p, _c, sockaddr in infos:
        label = "InterNetworkV6" if family == socket.AF_INET6 else "InterNetwork"
        entry = "%s %s" % (label, sockaddr[0])
        if entry not in seen:
            seen.add(entry)
            lines.append(entry)
    return "\n".join(lines)


def dns_servers() -> str:
    if hostos.IS_WINDOWS:
        return ps("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                  "Select-Object InterfaceAlias,ServerAddresses | "
                  "Format-Table -Auto | Out-String")
    if hostos.which("resolvectl"):
        return hostos.run_text(["resolvectl", "status"], timeout=15)
    return _read("/etc/resolv.conf") or "(no /etc/resolv.conf)"


# ══════════════════════════════════════════════════════════════════════════════
# OS-level connectivity opinion
# ══════════════════════════════════════════════════════════════════════════════

def interface_connectivity(name: str) -> str:
    """What the OS itself thinks the TUN's connectivity is.

    Windows: NCSI's IPv4Connectivity for that interface — the value that, when it
    reads LocalNetwork, silently switches off Spotlight, the Store and Widgets.
    Linux: NetworkManager's global connectivity verdict, which is per-host rather
    than per-interface and carries none of that consequence; it is reported for
    symmetry because it uses the same plaintext-HTTP probe path the port-80 route
    rule exists to fix.
    """
    if hostos.IS_WINDOWS:
        return ps("(Get-NetConnectionProfile -InterfaceAlias '" + name + "' "
                  "-ErrorAction SilentlyContinue).IPv4Connectivity").strip()
    if hostos.which("nmcli"):
        return hostos.run_text(["nmcli", "-t", "networking", "connectivity"],
                               timeout=10).strip()
    return ""


def connectivity_detail() -> str:
    if hostos.IS_WINDOWS:
        return ps("Get-NetConnectionProfile | Select-Object InterfaceAlias,Name,"
                  "NetworkCategory,IPv4Connectivity,IPv6Connectivity | "
                  "Format-Table -Auto | Out-String")
    if hostos.which("nmcli"):
        return hostos.run_text(
            ["nmcli", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
            timeout=10)
    return _ip("-brief", "addr")


# ══════════════════════════════════════════════════════════════════════════════
# who else is on the box
# ══════════════════════════════════════════════════════════════════════════════

def listening_ports() -> str:
    """Local listeners, so a port collision with ProxyForce's own is visible."""
    if hostos.IS_WINDOWS:
        return ps("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                  "Where-Object {$_.LocalAddress -eq '127.0.0.1'} | "
                  "Select-Object LocalAddress,LocalPort,OwningProcess | "
                  "Sort-Object LocalPort | Format-Table -Auto | Out-String")
    if hostos.which("ss"):
        return hostos.run_text(["ss", "-ltnp"], timeout=15)
    return hostos.run_text(["netstat", "-ltnp"], timeout=15)


def competing_agents() -> str:
    """Anything else that could be steering packets: another VPN/TUN, a filtering
    agent, or a policy-routing rule ProxyForce did not create. On Windows this is
    the third-party WFP layer question; on Linux it is other tun/wg/ppp interfaces
    plus the `ip rule` set, which is where a competing VPN shows up first."""
    if hostos.IS_WINDOWS:
        return ps("Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,"
                  "ifIndex,InterfaceMetric | Format-Table -Auto | Out-String")
    lines = ["--- interfaces ---", _ip("-brief", "link")]
    others = []
    try:
        for dev in sorted(os.listdir("/sys/class/net")):
            if re.match(r"^(tun|tap|wg|ppp|ipsec|utun|zt)", dev):
                others.append(dev)
    except OSError:
        pass
    lines.append("")
    lines.append("--- other tunnel interfaces: %s ---"
                 % (", ".join(others) if others else "none"))
    lines.append("")
    lines.append("--- ip rule (policy routing; a competing VPN appears here) ---")
    lines.append(_ip("rule", "show"))
    return "\n".join(lines)


def packet_filter_state(out_path: str = "") -> str:
    """The kernel's packet-filter configuration, in whatever form the platform has.

    Windows: a WFP state dump is a multi-megabyte XML file, so it is written to
    disk and this returns the path. Linux: the nftables ruleset (and legacy
    iptables NAT table, which is where sing-box's own redirect rules land on an
    older box) are small enough to inline.
    """
    if hostos.IS_WINDOWS:
        if not out_path:
            return "(no output path given)"
        ps("netsh wfp show state file=\"" + out_path + "\" | Out-Null", timeout=60)
        return out_path if os.path.isfile(out_path) else "(WFP dump not produced)"
    parts = []
    if hostos.which("nft"):
        parts.append("--- nft list ruleset ---\n" + hostos.run_text(
            ["nft", "list", "ruleset"], timeout=20))
    if hostos.which("iptables-save"):
        parts.append("--- iptables -t nat ---\n" + hostos.run_text(
            ["iptables-save", "-t", "nat"], timeout=20))
    return "\n\n".join(parts) if parts else "(neither nft nor iptables-save present)"
