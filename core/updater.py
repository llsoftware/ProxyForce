"""
ProxyForce — self-update pipeline.

ProxyForce is the machine's only internet path and runs elevated, so updating has
to be done carefully:

  * CHECK / DOWNLOAD / VERIFY happen while ProxyForce is running (it's the lifeline).
  * The offline SWAP + RELAUNCH happens with the proxy stopped — that's the brief
    no-connectivity window, which is why it's gated to off-hours / user confirm.
  * No UAC: ProxyForce already runs high-integrity, and a high-integrity process
    spawning a child never prompts. The downloaded build's OWN exe, run from the
    staging dir with `--apply-update`, swaps the install folder and relaunches.

Channels are the GitHub pre-release flag: "stable" follows full releases only,
"dev" follows the newest release including pre-releases. Promotion = clearing the
pre-release flag on a release (same signed artifact, no rebuild).

Integrity + authenticity: each release ships `SHA256SUMS` and a detached Ed25519
signature over it (`<zip>.sig`). We verify the signature with the embedded public
key, then check the zip's SHA-256 is the one listed. Verification uses the vendored
pure-Python Ed25519 (`core/_ed25519.py`) — no binary crypto dependency.

Stdlib only.
"""

import os
import sys
import re
import json
import time
import base64
import hashlib
import zipfile
import shutil
import subprocess
import urllib.request
import urllib.parse

from core import _ed25519
from core._version import __version__ as APP_VERSION

# ── repo / release identity ───────────────────────────────────────────────────
REPO = "llsoftware/ProxyForce"
_API = f"https://api.github.com/repos/{REPO}"
_UA = "ProxyForce-Updater"

# Ed25519 public key (base64, 32 bytes) used to verify release signatures. Generated
# once by `python tools/gen_keypair.py`; paste its PUBLIC key here. The matching
# private seed lives ONLY in the GitHub Actions secret PROXYFORCE_SIGNING_KEY and is
# never committed. Empty key ⇒ verify() fails closed (no unsigned update can install).
RELEASE_PUBKEY_B64 = "6718APpvsP0uJfLY96Z+gBdbz6GkMjO/XA6ZiJwLKt4="

# ── Windows process-creation flags ────────────────────────────────────────────
_CREATE_NO_WINDOW = 0x08000000
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000

# Post-relaunch health check: poll the new build this many times at this interval; if
# it's still up at the end, the swap is committed (else rolled back). Module-level so
# tests can shrink them.
_HEALTH_CHECKS = 8
_HEALTH_INTERVAL = 1.0


# ── paths ─────────────────────────────────────────────────────────────────────
def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def update_dir() -> str:
    return os.path.join(_data_dir(), "update")


def _state_path() -> str:
    return os.path.join(update_dir(), "state.json")


def load_state() -> dict:
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict):
    try:
        os.makedirs(update_dir(), exist_ok=True)
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


# ── version comparison (semver-ish with pre-release precedence) ───────────────
def parse_version(s: str):
    """Return (release_tuple, prerelease_ids_or_None). 'v2.1.11-beta.2' →
    ((2,1,11), ['beta','2']); '2.1.11' → ((2,1,11), None)."""
    s = (s or "").strip().lstrip("vV")
    core, _, pre = s.partition("-")
    nums = re.findall(r"\d+", core)
    rel = tuple(int(n) for n in nums) if nums else (0,)
    return rel, (pre.split(".") if pre else None)


def _cmp_prerelease(a, b) -> int:
    """SemVer §11 precedence for pre-release identifier lists."""
    for x, y in zip(a, b):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            c = (int(x) > int(y)) - (int(x) < int(y))
        elif xn != yn:
            c = -1 if xn else 1            # numeric identifiers rank lower
        else:
            c = (x > y) - (x < y)
        if c:
            return c
    return (len(a) > len(b)) - (len(a) < len(b))


def version_gt(a: str, b: str) -> bool:
    """True iff version `a` is strictly newer than `b`."""
    ra, pa = parse_version(a)
    rb, pb = parse_version(b)
    n = max(len(ra), len(rb))
    la = list(ra) + [0] * (n - len(ra))
    lb = list(rb) + [0] * (n - len(rb))
    if la != lb:
        return la > lb
    if pa is None and pb is None:
        return False
    if pa is None:                          # a final, b pre-release → a newer
        return True
    if pb is None:                          # a pre-release, b final → a older
        return False
    return _cmp_prerelease(pa, pb) > 0


def current_version() -> str:
    return APP_VERSION


# ── update metadata ───────────────────────────────────────────────────────────
class UpdateInfo:
    def __init__(self, tag, prerelease, zip_url, sums_url, sig_url):
        self.tag = tag
        self.version = tag.lstrip("vV")
        self.prerelease = bool(prerelease)
        self.zip_url = zip_url
        self.sums_url = sums_url
        self.sig_url = sig_url
        self.zip_name = f"ProxyForce-{tag}-win64.zip"
        self.sig_name = self.zip_name + ".sig"

    def __repr__(self):
        return f"<UpdateInfo {self.tag} prerelease={self.prerelease}>"


# ── HTTP via the configured corporate proxy ───────────────────────────────────
def _opener(cfg: dict):
    """A urllib opener that egresses through the configured corporate proxy, so the
    update check/download works regardless of the current system-proxy state."""
    host = (cfg.get("host") or "").strip()
    port = cfg.get("port")
    if not host:
        return urllib.request.build_opener()
    auth = ""
    if cfg.get("auth_type") == "basic" and cfg.get("username"):
        u = urllib.parse.quote(str(cfg.get("username")), safe="")
        p = urllib.parse.quote(str(cfg.get("password") or ""), safe="")
        auth = f"{u}:{p}@"
    proxy = f"http://{auth}{host}:{port}"
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))


def _api_get(opener, url):
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": _UA})
    with opener.open(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _release_to_info(rel):
    """Build an UpdateInfo from a GitHub release JSON object, or None if it lacks the
    expected signed assets."""
    if not rel or rel.get("draft"):
        return None
    tag = rel.get("tag_name")
    if not tag:
        return None
    assets = {a["name"]: a.get("browser_download_url") for a in (rel.get("assets") or [])}
    zip_name = f"ProxyForce-{tag}-win64.zip"
    zip_url = assets.get(zip_name)
    sums_url = assets.get("SHA256SUMS")
    sig_url = assets.get(zip_name + ".sig")
    if not (zip_url and sums_url and sig_url):
        return None
    return UpdateInfo(tag, rel.get("prerelease"), zip_url, sums_url, sig_url)


def check_latest(cfg: dict):
    """Return an UpdateInfo if the selected channel has a release strictly newer than
    the running version, else None. Channel comes from cfg['update_channel']."""
    opener = _opener(cfg)
    channel = (cfg.get("update_channel") or "stable").lower()
    candidate = None
    if channel == "dev":
        # Newest by version across all non-draft releases (pre-releases included).
        for rel in _api_get(opener, f"{_API}/releases?per_page=30"):
            info = _release_to_info(rel)
            if info and (candidate is None or version_gt(info.tag, candidate.tag)):
                candidate = info
    else:
        # /releases/latest is by definition the newest non-prerelease, non-draft.
        candidate = _release_to_info(_api_get(opener, f"{_API}/releases/latest"))
    if candidate and version_gt(candidate.tag, APP_VERSION):
        return candidate
    return None


# ── download ──────────────────────────────────────────────────────────────────
def _download_file(opener, url, dest, progress_cb=None):
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, "Accept": "application/octet-stream"})
    with opener.open(req, timeout=120) as r:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress_cb:
                    progress_cb(done, total)
    return dest


def download(info: UpdateInfo, cfg: dict, progress_cb=None) -> str:
    """Download the zip + SHA256SUMS + signature into update/<tag>/. progress_cb is
    called as progress_cb(bytes_done, bytes_total) for the (large) zip download."""
    opener = _opener(cfg)
    ddir = os.path.join(update_dir(), info.tag)
    os.makedirs(ddir, exist_ok=True)
    # Small sidecars first (cheap, no progress), then the zip with progress.
    _download_file(opener, info.sums_url, os.path.join(ddir, "SHA256SUMS"))
    _download_file(opener, info.sig_url, os.path.join(ddir, info.sig_name))
    _download_file(opener, info.zip_url, os.path.join(ddir, info.zip_name), progress_cb)
    return ddir


# ── verify (Ed25519 over SHA256SUMS + SHA-256 of the zip) ─────────────────────
def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(info: UpdateInfo, ddir: str) -> bool:
    """True iff the signature over SHA256SUMS is valid under the embedded public key
    AND the downloaded zip's SHA-256 matches the entry in SHA256SUMS. Fails closed."""
    zip_path = os.path.join(ddir, info.zip_name)
    sums_path = os.path.join(ddir, "SHA256SUMS")
    sig_path = os.path.join(ddir, info.sig_name)
    if not all(os.path.isfile(p) for p in (zip_path, sums_path, sig_path)):
        return False
    try:
        pub = base64.b64decode(RELEASE_PUBKEY_B64) if RELEASE_PUBKEY_B64 else b""
    except Exception:
        return False
    if len(pub) != 32:
        return False
    with open(sums_path, "rb") as f:
        sums = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    if not _ed25519.verify(pub, sums, sig):
        return False
    want = _sha256(zip_path).lower()
    for line in sums.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == want \
                and parts[-1].lstrip("*").endswith(info.zip_name):
            return True
    return False


# ── stage (extract) + selftest gate ──────────────────────────────────────────
def stage(info: UpdateInfo, ddir: str) -> str:
    """Extract the verified zip to update/<tag>/staged and return that path. The zip
    contains the onedir layout (ProxyForce.exe + _internal\\) at its root."""
    staged = os.path.join(ddir, "staged")
    if os.path.isdir(staged):
        shutil.rmtree(staged, ignore_errors=True)
    os.makedirs(staged, exist_ok=True)
    with zipfile.ZipFile(os.path.join(ddir, info.zip_name)) as z:
        z.extractall(staged)
    return staged


def selftest_staged(staged: str) -> bool:
    """Run the staged build's own --selftest as a pre-swap gate (verifies imports +
    `sing-box check`). Returns True only on a clean pass."""
    exe = os.path.join(staged, "ProxyForce.exe")
    if not os.path.isfile(exe):
        return False
    try:
        r = subprocess.run([exe, "--selftest"], capture_output=True, text=True,
                           creationflags=_CREATE_NO_WINDOW, timeout=120)
        return r.returncode == 0
    except Exception:
        return False


# ── apply: spawn the elevated worker, then the GUI exits ──────────────────────
def begin_apply(staged: str, install_dir: str, wait_pid: int,
                relaunch_args: str = "--minimized"):
    """Spawn the staged build's exe as a detached, elevated worker that waits for
    this process (wait_pid) to exit, swaps the install folder, and relaunches. The
    caller must then stop the proxy and exit promptly."""
    exe = os.path.join(staged, "ProxyForce.exe")
    # Relaunch is always "--minimized" (resume-after-update is driven by state.json,
    # not args) — so we don't pass an arg value that itself starts with "--".
    args = [exe, "--apply-update", "--target", install_dir, "--wait-pid", str(wait_pid)]
    flags = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_BREAKAWAY_FROM_JOB
    try:
        subprocess.Popen(args, cwd=staged, close_fds=True, creationflags=flags)
    except OSError:
        # Job disallows breakaway (rare; GUI isn't normally in a job) — retry without.
        subprocess.Popen(args, cwd=staged, close_fds=True,
                         creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP)


# ── apply worker (runs from the staged copy, --apply-update) ──────────────────
def _parse_kv(argv):
    """Parse `--key value` pairs after --apply-update."""
    out = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            out[a[2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return out


def _wait_pid_exit(pid: int, timeout: float):
    if not pid:
        return
    import ctypes
    SYNCHRONIZE = 0x00100000
    h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, int(pid))
    if not h:
        return                                  # already gone
    try:
        ctypes.windll.kernel32.WaitForSingleObject(h, int(timeout * 1000))
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


def _spawn(exe: str, relaunch_args: str):
    args = [exe] + (relaunch_args.split() if relaunch_args else [])
    return subprocess.Popen(args, cwd=os.path.dirname(exe), close_fds=True,
                            creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP)


def _retry(fn, tries=10, delay=1.0):
    last = None
    for _ in range(tries):
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(delay)
    if last:
        raise last


def _applog(msg: str):
    try:
        os.makedirs(update_dir(), exist_ok=True)
        with open(os.path.join(update_dir(), "apply.log"), "a", encoding="utf-8") as f:
            f.write(f"{msg}\n")
    except Exception:
        pass


def apply_worker(argv):
    """The `--apply-update` worker. Runs from the staged copy with the install dir
    free to overwrite. Waits for the outgoing process to exit, then swaps."""
    opts = _parse_kv(argv)
    target = opts.get("target")
    wait_pid = int(opts.get("wait-pid") or 0)
    staged = os.path.dirname(os.path.abspath(sys.executable))
    _applog(f"apply start: target={target} staged={staged} wait_pid={wait_pid}")
    _wait_pid_exit(wait_pid, timeout=120)
    time.sleep(1.0)                             # let handles/AV release
    _apply_swap(staged, target, "--minimized")


def _apply_swap(staged: str, target: str, relaunch: str) -> bool:
    """Back up the install dir, copy the staged build in, relaunch it, and roll back
    if the new build doesn't stay up. Returns True on a committed, healthy swap."""
    target_exe = os.path.join(target, "ProxyForce.exe")
    backup = target.rstrip("\\/") + ".old"

    try:
        if os.path.isdir(backup):
            shutil.rmtree(backup, ignore_errors=True)
        _retry(lambda: os.rename(target, backup))   # move old aside
        # dirs_exist_ok so a retry after a partial copy doesn't trip FileExistsError.
        _retry(lambda: shutil.copytree(staged, target, dirs_exist_ok=True))  # install new
        _applog("swap ok")
    except Exception as e:
        _applog(f"swap FAILED: {e!r} — rolling back")
        if not os.path.isdir(target) and os.path.isdir(backup):
            try:
                os.rename(backup, target)
            except Exception as e2:
                _applog(f"rollback rename failed: {e2!r}")
        if os.path.isfile(target_exe):
            _spawn(target_exe, relaunch)
        return False

    # Relaunch the new build (elevated child of this elevated worker → no UAC).
    try:
        proc = _spawn(target_exe, relaunch)
    except Exception as e:
        _applog(f"relaunch spawn failed: {e!r} — rolling back")
        proc = None

    # Health check: did the new build stay up?
    healthy = False
    if proc is not None:
        for _ in range(_HEALTH_CHECKS):
            if proc.poll() is not None:
                break
            time.sleep(_HEALTH_INTERVAL)
        healthy = proc.poll() is None

    if not healthy:
        _applog("new build did not stay up — rolling back to .old")
        shutil.rmtree(target, ignore_errors=True)
        try:
            os.rename(backup, target)
        except Exception as e:
            _applog(f"rollback failed: {e!r}")
        if os.path.isfile(target_exe):
            _spawn(target_exe, relaunch)
        return False

    # Success: drop the backup. The staged dir (this worker's own folder) is removed
    # by the freshly-launched instance via cleanup_staging() once we exit.
    shutil.rmtree(backup, ignore_errors=True)
    _applog("apply complete")
    return True


def cleanup_staging(keep_tag: str = None):
    """Best-effort removal of update/<tag> folders (called by a freshly-started
    instance). Skips anything still locked."""
    base = update_dir()
    if not os.path.isdir(base):
        return
    for name in os.listdir(base):
        if name in ("state.json", "apply.log") or name == keep_tag:
            continue
        path = os.path.join(base, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
