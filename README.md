# ProxyForce

Transparent corporate-proxy redirector for Windows.
**Forces ALL outbound TCP through a corporate HTTP proxy via CONNECT — including
apps that are hardcoded to ignore proxy settings (e.g. AnythingLLM).** Capture
happens at the network layer (a TUN adapter), so it doesn't depend on any app
cooperating. ProxyForce also points the Windows system proxy at its own local
listeners while it runs (so proxy-aware apps — including the Microsoft Edge updater
— route through ProxyForce instead of around it) and suppresses IPv6 (AAAA) so
dual-stack apps fall back to IPv4 — nothing leaks around the proxy.

Works on **Windows 10 22H2+** and **Windows 11**, on bare metal and in VMs
(VMware, Hyper-V, VirtualBox).

---

## How It Works

```
Any App → [sing-box TUN adapter] → ProxyForce (elevated GUI) → [HTTP CONNECT] → Corporate Proxy → Internet
```

- A **sing-box** process (bundled, no separate install) creates a virtual TUN
  network adapter using the **Wintun** driver (embedded in sing-box). ProxyForce
  forces the TUN to win the routing table with split-default routes
  (`0.0.0.0/1` + `128.0.0.0/1`) — these beat the physical NIC by longest-prefix
  match, so capture works regardless of interface metrics. sing-box's own
  connection to the proxy is excluded with a `/32` host route so it never loops
  back into its own tunnel.
- All TCP traffic enters the TUN interface. sing-box intercepts DNS with **fakeip**
  so it always knows the target hostname, then issues `CONNECT <hostname>:port` to
  your corporate proxy. Because capture is at the network layer, this works even
  for apps that are hardcoded to ignore proxy settings — no per-app config needed.
- **The Windows system proxy points at ProxyForce while it runs** (both the per-user
  WinINET setting *and* machine-wide WinHTTP), then is restored exactly as it was on
  stop. It is set **protocol-split** so each scheme takes its working path: **HTTPS**
  goes to sing-box's local listener (`CONNECT`, native and fast), while **plaintext
  HTTP** goes to a small local **forward-proxy** that relays it to the corporate proxy
  as a normal `GET http://…`. That split is what fixes the **Microsoft Edge updater**
  (error `0x80072EFE`): Edge downloads its payload via Delivery Optimization over
  **plaintext HTTP on port 80**, and many corporate proxies (including the one this was
  diagnosed against) allow `CONNECT` only to :443 and return **403** to `CONNECT` on
  :80 — so port-80 traffic must leave as a forward-proxy `GET`, which it now does.
  Loopback/intranet and your bypass list stay direct. The TUN remains the catch-all for
  apps that ignore proxy settings. The original is snapshotted to
  `C:\ProgramData\ProxyForce\proxy_backup.json`, so it's restored even after a crash.
- **Plaintext HTTP captured by the TUN is also handled**, not just the proxy-aware
  half above. Anything that ignores Windows' proxy setting entirely — Windows' own
  connectivity check (NCSI), WPAD auto-discovery, or any app hardcoded to bypass
  proxy config — has its port-80 traffic redirected into the same local forward-proxy
  by a sing-box route rule. Without this, NCSI's own probe got **403**'d by the
  corporate proxy the same way the Edge updater did, and Windows concluded it had
  **no internet** (`IPv4Connectivity: LocalNetwork`) — silently stopping Windows
  Spotlight, Microsoft Store, Widgets, and anything else that gates on connectivity
  level from refreshing. See **Troubleshooting → Windows Spotlight** below.
- **IPv6 is suppressed** (AAAA answered with NODATA) so dual-stack apps fall back to
  IPv4 → fakeip → proxy. The TUN is IPv4-only by design (avoids a Windows 10 IPv6
  crash); suppressing AAAA is what stops IPv6 from leaking around the proxy.
- **Microsoft Store / UWP apps get a loopback exemption for as long as ProxyForce
  runs.** Every Store app runs inside an AppContainer, which Windows blocks from
  reaching `127.0.0.1` by default — so pointing the system proxy at ProxyForce's
  local listeners (above) would otherwise leave the Store, Mail, Xbox, and every
  other UWP app unable to reach it at all (not "bypassing capture" — the OS kills
  the connection before it leaves the app, so the TUN can't rescue it either).
  ProxyForce runs `CheckNetIsolation LoopbackExempt -a` for every installed package
  on start (and re-sweeps periodically for apps installed while it's running), and
  removes exactly what it added on stop — snapshotted the same way as the system
  proxy, so a crash doesn't leave the machine permanently loosened.
- **UDP is rejected** (including QUIC/HTTP3 on UDP/443). Proxy-aware apps don't try
  QUIC at all (a proxy is configured); anything that does falls back to TCP, which is
  captured. DNS is the one exception — it's hijacked to fakeip.
- **New connections are captured automatically — no app restart needed.** A TCP
  connection that was already open before you hit Start keeps its old path until it
  closes (the OS can't reroute a live socket); anything opened after Start is
  captured from its first packet.
- The **GUI** owns and manages sing-box directly as a child process. Closing the
  window minimises to the **system tray** — enforcement keeps running until you
  choose **Quit** from the tray menu.
- Config is stored **machine-wide** in `HKLM\SOFTWARE\ProxyForce` (with a
  `C:\ProgramData\ProxyForce\config.json` fallback).

---

## Requirements

| | |
|---|---|
| **OS** | Windows 10 22H2+ or Windows 11 (64-bit) |
| **Privileges** | Administrator (UAC prompt on every launch) |
| **Network** | HTTP proxy reachable from the machine |
| **Dependencies** | None — everything is bundled in the release folder |

> **QUIC / HTTP3 note:** HTTP CONNECT is TCP-only, so ProxyForce **rejects all UDP**
> (including QUIC on UDP/443) — apps automatically fall back to TCP, which is
> captured. No firewall rule is required; blocking UDP/443 at the firewall is just
> optional belt-and-suspenders.

---

## Install (from Release)

1. Download `ProxyForce-vX.Y.Z-win64.zip` from the [Releases](../../releases) page.
2. Extract the zip to any folder (e.g. `C:\Tools\ProxyForce\`).
3. Double-click `ProxyForce.exe` inside the extracted folder and approve the UAC prompt.
4. Open the **Settings** tab, enter your proxy host and port, click **Save Config**.
5. Click **▶ Start Proxy** — the status indicator turns green when traffic is flowing.

No install wizard, no service to register. The folder can live anywhere.

> **Keep the folder intact** — `ProxyForce.exe` must stay alongside its `_internal\`
> sibling folder. Moving just the exe will break it.

---

## Usage

| Action | How |
|---|---|
| Start redirecting | Click **▶ Start Proxy** (or use the tray menu) |
| Stop redirecting | Click **■ Stop Proxy** (or use the tray menu) |
| Minimise to tray | Click the window **×** button |
| Quit completely | **Tray icon → Quit** (stops sing-box and exits) |
| Save settings | **Settings tab → Save Config** |
| Test proxy reachability | **Settings tab → Test Proxy** |
| Switch light/dark theme | Toggle in the header: ☀ Light · 🖥 Auto · 🌙 Dark |

> **Enforcement lifetime:** redirection runs while ProxyForce is in the tray.
> It stops when you Quit or when the process ends. There is no background
> Windows service; UAC elevation is required each time you launch the app.

> **Your Windows proxy setting while running:** ProxyForce temporarily **points** the
> Windows system proxy (Settings ▸ Network ▸ Proxy, and `netsh winhttp`) at its own
> local listener (`127.0.0.1:<port>`) so proxy-aware apps route through ProxyForce
> over TCP rather than bypassing it or attempting QUIC. This is expected — it's
> automatically restored to your exact previous setting when you Stop or Quit (and
> recovered from a backup file
> even if the app crashes). The port is a **fixed default** (18080/18081/18089) that
> stays the same across an ordinary restart, so an already-open command-line tool
> (a shell, an editor's agent/CLI, anything reading `HTTP_PROXY`/`HTTPS_PROXY`) keeps
> working without needing to be reopened — it only needs reopening the very first
> time, to pick up the value at all. If something else on the machine is already
> using one of those ports, ProxyForce falls back to an ephemeral one for just that
> slot (logged in the Log tab) and that one case still needs a reopen.

---

## Updates

ProxyForce can keep itself current from GitHub Releases.

- **Manual check:** Settings ▸ **Check for Updates** (or the tray **Check for updates**).
- **Nightly check:** enable *Check for updates nightly* in Settings and pick the hour
  (default 03:00 local). While ProxyForce is running it checks once a day, then
  **downloads + verifies** the new build in the background — without interrupting
  connectivity.
- **Applying is on your confirmation.** When a verified build is ready you choose
  **Install now** (a brief disconnect, then ProxyForce relaunches and reconnects) or
  **Install tonight at HH:00** (the swap happens silently off-hours). The actual
  file-swap is the only step that needs the proxy stopped, so it's never done without
  your say-so.

**Why it's safe.** Each release ships a `SHA256SUMS` and a detached **Ed25519
signature** over it. ProxyForce verifies the signature with a public key baked into
the app, then checks the download's SHA-256 — so a corrupted *or* tampered/hijacked
release is rejected. The staged build must also pass its own `--selftest` before the
swap, and the previous version is kept as a rollback target in case the new one fails
to start.

Update assets are stored in a randomly named, administrator-only workspace under
`%ProgramData%`. Downloads are bounded and atomic, unsafe archive paths and links are
rejected, and the signed archive is verified and freshly extracted again immediately
before installation. The new build must emit a positive readiness signal or the
updater rolls back.

ProxyForce remains portable and is not Authenticode-signed. Keep its folder in a
trusted location: software already running as the same Windows user may otherwise
replace portable files between launches. In-updater release authenticity is provided
by the embedded Ed25519 key.

### Channels — Development vs Stable

Pick a channel in Settings (per machine, default **Stable**):

| Channel | Gets |
|---|---|
| **Stable** | Full releases only (production). |
| **Development** | The newest release, **including pre-releases** (test builds). |

Every release is published as a GitHub **pre-release** first, so Development machines
get it for testing. Once you're happy, **promote it to Stable** (same signed
artifact, no rebuild):

```
gh release edit vX.Y.Z --prerelease=false
```

Stable machines pick it up on their next check.

---

## Build from Source

Releases are built automatically by GitHub Actions on every `v*` tag.
To build locally:

1. Install Python 3.11+ (64-bit) and run:
   ```
   pip install customtkinter pystray pillow pyinstaller
   ```
2. Generate the icon:
   ```
   python tools/make_assets.py
   ```
3. Run PyInstaller:
   ```
   python -m PyInstaller proxyforce_onefile.spec --clean --noconfirm
   ```
4. Output: **`dist\ProxyForce\`** — zip the folder and distribute it.

> **Note:** CI additionally rebuilds the PyInstaller bootloader from source before
> packaging, which further reduces AV false-positive rates. Local builds skip this
> step by default; it is only required for public release artifacts.

---

## Command-Line Arguments

| Argument | Effect |
|---|---|
| (none) | Open the GUI |
| `--minimized` | Start hidden in the system tray |
| `--selftest` | Build-machine smoke test: verify imports + sing-box; exit 0 on pass |

---

## Troubleshooting

> **First stop for any issue: the diagnostics report.** A few seconds after you hit
> Start, ProxyForce writes a full self-check to
> `C:\ProgramData\ProxyForce\diagnostics.txt` and streams the same checkpoints live
> into the **Log** tab (TUN adapter → capture routes → DNS→fakeip → proxy reachable
> → system proxy → ProxyForce), ending in a one-line **VERDICT**. The Log tab also
> shows each connection as it's made — `conn  host:port  ->  proxy` (captured) or
> `-> direct (bypass)`. Read the VERDICT first; it usually names the exact problem.

**Redirect won't start / status shows ERROR**
Check the **Log** tab and `C:\ProgramData\ProxyForce\singbox\singbox.log` — the
last error lines appear in the GUI event log automatically. Common causes:

- Another TUN/VPN adapter has the same interface name (`ProxyForce`) — rename or
  remove it before starting.
- The process is not running elevated — the UAC manifest should handle this, but
  verify via Task Manager (the process should show "High" mandatory level).

**Traffic is not going through the proxy**
- Confirm ProxyForce shows **ACTIVE** (green beacon), then read the **VERDICT** in
  `diagnostics.txt` — it pinpoints the stage that failed.
- In the **Log** tab, watch the live `conn ... -> proxy` lines. Public hosts going
  `-> direct` are bypassing capture; no lines at all means no new connections were
  made (open a page to generate some).
- A connection that was already open before Start keeps its old path — open a new
  page or restart that app to force a fresh, captured connection.
- If a browser still goes direct, disable its **Secure DNS (DoH)** — DoH resolves
  names inside an encrypted tunnel that skips ProxyForce's fakeip DNS.
- For deep route/WFP analysis, `C:\ProgramData\ProxyForce\singbox\singbox.log` and
  `wfp_state.xml` (next to `diagnostics.txt`) hold the raw evidence.

**A proxy-aware app (browser) still bypasses ProxyForce while it's running**
ProxyForce points the Windows system proxy at its own local listener on Start, but a
corporate **Group Policy** can re-push a different proxy/PAC over it. Check the
**"System proxy"** section of `diagnostics.txt`: a WARN there means a GPO or a per-app
proxy overrode it (it no longer points at `127.0.0.1:<port>`). GPO-enforced proxies
must be cleared by policy (or the app's own proxy setting changed); the TUN still
captures everything else regardless.

**Microsoft Store (or another Store/UWP app) won't load**
UWP apps run in an AppContainer, which Windows blocks from reaching loopback
(`127.0.0.1`) unless exempted — and ProxyForce's system-proxy takeover points there.
ProxyForce grants the exemption automatically on Start (`CheckNetIsolation
LoopbackExempt -a`, one per installed package) and removes it on Stop. Check the
**"Store/UWP loopback exemption"** section of `diagnostics.txt` — a FAIL there (or a
`DIAG: UWP LOOPBACK BLOCKED` verdict) means the sweep didn't complete or was denied.
Verify from an elevated prompt:
```bat
CheckNetIsolation LoopbackExempt -s
```
It should list every installed package (~100+, including
`microsoft.windowsstore_8wekyb3d8bbwe`) while ProxyForce is running, and be empty
again after Stop. An empty list while ProxyForce is ACTIVE means the sweep failed —
most likely ProxyForce lost elevation (see "Redirect won't start" above for the UAC
check) or ran before it, since `CheckNetIsolation -a` itself requires admin.

**Windows Spotlight / lock screen images don't update while ProxyForce is running**
This is a symptom of Windows itself believing it has **no internet**, not a Spotlight
problem — `ContentDeliveryManager` (and Microsoft Store, Widgets, Teams presence, and
anything else that checks connectivity level) silently stops refreshing content when
that happens, with no visible error anywhere.

The cause is Windows' own connectivity check, **NCSI**: it makes two probes — a DNS
lookup and an HTTP request — that both bypass the Windows system proxy setting
entirely (NCSI runs as a system service and never honors WinINET/WinHTTP). Before the
port-80 route rule and the DNS fix below existed, NCSI's DNS probe got a fakeip
address instead of the literal answer it requires, and its HTTP probe got the same
**403** the Microsoft Edge updater used to get on plaintext port 80 — so Windows
concluded `IPv4Connectivity: LocalNetwork` ("no internet") even while everything else
worked fine.

**Diagnose:**
```powershell
Get-NetConnectionProfile | Select-Object InterfaceAlias, IPv4Connectivity
```
`Internet` is healthy; `LocalNetwork`/`NoTraffic`/`Subnet` means Windows agrees with
the symptom. `diagnostics.txt`'s **"NCSI connectivity"** / **"NCSI DNS probe"** /
**"NCSI web probe"** sections (and a `NO INTERNET (NCSI)` verdict) show exactly which
probe is failing.

**Fix:** ProxyForce keeps NCSI active probing enabled, answers its DNS probe with the
exact literal it expects, and routes its HTTP probe through the local forward-proxy
that fixes plaintext port 80. Startup diagnostics wait for a quiet NCSI probe window
instead of launching a burst of subprocesses at the same time. If the ProxyForce
profile is still not `Internet`, ProxyForce re-announces the proxy configuration once
and allows a second quiet window before producing diagnostics.

The report checks the **ProxyForce** profile specifically and includes the latest
matching NCSI Operational event (`ActiveHttpProbeFailedButDnsSucceeded`,
`SuspectDnsProbeFailed`, and similar reasons), rather than treating another adapter's
`Internet` state as success. ProxyForce no longer disables `EnableActiveProbing`;
Microsoft advises that passive polling alone cannot determine every connectivity
state.

**A destination the corporate proxy refuses (Outlook/mail, or anything else)**
Many corporate proxies permit HTTP `CONNECT` only to **:443** (or otherwise refuse
specific ports/hosts by policy) and answer with a **403** — the same restriction
documented above for the Microsoft Edge updater on plaintext :80. Every network's
policy is different (mail ports are one common case, but ProxyForce has seen
internal/internal-only hosts refused on arbitrary ports too). ProxyForce does not
add exceptions on its own — route the refused destination(s) DIRECT yourself:

1. Settings ▸ **Bypass List** ▸ add the destination hostname(s), e.g.
   `imaps.example.com` and `smtps.example.com` for mail (one per line — CIDRs and
   `*.example.com` wildcards work too). Save; ProxyForce restarts to apply it.
2. **Fully exit** the affected app (check Task Manager, not just the window) and
   relaunch — it must re-resolve and re-connect on the new rules, not reuse a
   connection it made before the change.
3. Settings ▸ **Test Proxy** now sends a real `CONNECT` on :443/:80/:993/:465/:587
   and reports each port's actual status — a `403` there tells you definitively
   this proxy refuses that port, rather than a bare "reachable" that says nothing
   about policy. `diagnostics.txt`'s **"Proxy CONNECT policy"** section reports
   the same thing after the fact, sourced from sing-box's own log.

If the destination isn't reachable at all without ProxyForce running either, this
won't help — bypassing only works for hosts your network can already reach
directly. Note also that for IMAPS/SMTPS specifically there is no forward-proxy
workaround the way there is for plaintext HTTP: mail isn't HTTP, so it can't be
relayed as a `GET` — direct routing (automatic or manual) is the only fix.

**407 Proxy Authentication Required**
Wrong credentials or auth type. Open Settings and check username/password/auth type —
in particular, Auth Type must be **Basic** for a username/password to be sent at all;
Settings shows a warning (and the Log tab logs one on Save/Connect) if Auth Type is
**None** or **NTLM** while credentials are filled in, since neither of those sends them.

**SSL errors / certificate warnings**
Push your corporate CA certificate to Trusted Root via GPO:
```bat
certutil -addstore Root YourCA.crt
```

**Windows Defender flags the download as a virus/trojan**
This is a known false positive (`Sabsik.TE.A!ml` — a machine-learning heuristic)
that sometimes fires on unsigned network-proxy tools. To allow it:

1. Go to **Windows Security → Virus & threat protection → Protection history**.
2. Find the quarantined item and click **Allow** (or **Restore**).
3. Alternatively, add a Defender **Exclusion** for the folder *before* extracting.
4. After extracting, run this in PowerShell to clear the Mark-of-the-Web flag:
   ```powershell
   Get-ChildItem -Recurse "C:\Tools\ProxyForce\" | Unblock-File
   ```

We submit every release to [Microsoft's false-positive portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
to clear the hash via cloud definitions (~2–5 business days after release).

**Windows SmartScreen blocks the exe**
Click *More info → Run anyway* for internal deployments. SmartScreen reputation
builds automatically as more users run the app.

**System tray icon missing**
pystray requires a system tray to be available (Explorer shell). It is present by
default on all standard Windows installs. If running in a minimal/headless session,
the tray may be unavailable — use `--minimized` and manage the process via Task
Manager.

---

## Security Notes

- Passwords are base64-obfuscated in `HKLM`. For production, replace with a
  machine-scoped DPAPI blob in `core/config_store.py`.
- Whitelist the ProxyForce folder and `_internal\singbox\sing-box.exe` in AV/EDR
  if those paths are quarantined. (sing-box lives on disk in `_internal\singbox\`
  inside the extracted zip — it is NOT extracted to `%TEMP%` at runtime.)
