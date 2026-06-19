# ProxyForce

Transparent corporate-proxy redirector for Windows.
**Forces ALL outbound TCP through a corporate HTTP proxy via CONNECT — including
apps that are hardcoded to ignore proxy settings (e.g. AnythingLLM).** Capture
happens at the network layer (a TUN adapter), so it doesn't depend on any app
cooperating. ProxyForce also points the Windows system proxy at its own local
sing-box listener while it runs (so proxy-aware apps route through ProxyForce over
TCP — and don't attempt QUIC/direct around it) and suppresses IPv6 (AAAA) so
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
- **The Windows system proxy points at ProxyForce's own local sing-box listener
  while it runs** (both the per-user WinINET setting *and* machine-wide WinHTTP),
  then is restored exactly as it was on stop. Proxy-aware apps (browsers, the
  Microsoft Edge updater, …) therefore send `CONNECT` to ProxyForce over TCP and
  sing-box forwards them to the corporate proxy — they never believe they're on
  direct internet and never attempt HTTP-3/QUIC (which the UDP reject below kills;
  that was the cause of Edge update error `0x80072EFE`). Loopback/intranet and your
  bypass list stay direct. The TUN remains the catch-all for apps that ignore proxy
  settings. The original is snapshotted to
  `C:\ProgramData\ProxyForce\proxy_backup.json`, so it's restored even after a crash.
- **IPv6 is suppressed** (AAAA answered with NODATA) so dual-stack apps fall back to
  IPv4 → fakeip → proxy. The TUN is IPv4-only by design (avoids a Windows 10 IPv6
  crash); suppressing AAAA is what stops IPv6 from leaking around the proxy.
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
> even if the app crashes).

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

### Enabling signing (one-time, maintainers)

```
python tools/gen_keypair.py
```

Add the printed **private seed** as the repo Actions secret `PROXYFORCE_SIGNING_KEY`,
and paste the printed **public key** into `core/updater.py` → `RELEASE_PUBKEY_B64`.
Until this is configured, releases build unsigned and the auto-updater refuses them
(manual install still works).

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

**407 Proxy Authentication Required**
Wrong credentials or auth type. Open Settings and check username/password/auth type.

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
