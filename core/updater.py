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
import secrets
import stat

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

_MAX_SIDECAR = 64 * 1024
_MAX_ARCHIVE = 250 * 1024 * 1024
_MAX_EXTRACTED = 750 * 1024 * 1024
_MAX_MEMBERS = 5000
_TAG_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


# ── paths ─────────────────────────────────────────────────────────────────────
def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def update_dir() -> str:
    return os.path.join(_data_dir(), "update-v2")


def _legacy_update_dir() -> str:
    return os.path.join(_data_dir(), "update")


def _is_reparse(path: str) -> bool:
    try:
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return False


def _assert_beneath(path: str, root: str):
    root_abs = os.path.normcase(os.path.abspath(root)).rstrip("\\/")
    path_abs = os.path.normcase(os.path.abspath(path))
    if path_abs != root_abs and not path_abs.startswith(root_abs + os.sep):
        raise ValueError("update path escapes protected root")


def _assert_no_reparse(path: str, root: str):
    _assert_beneath(path, root)
    cur = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    while True:
        if os.path.lexists(cur) and _is_reparse(cur):
            raise ValueError(f"reparse point rejected: {cur}")
        if os.path.normcase(cur) == os.path.normcase(root_abs):
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            raise ValueError("protected root not reached")
        cur = parent


def _harden_acl(path: str):
    """Protect an update directory using language-independent Windows SIDs."""
    if os.name != "nt":
        return
    commands = (
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", "*S-1-5-18:(OI)(CI)F",
         "*S-1-5-32-544:(OI)(CI)F"],
        ["icacls", path, "/setowner", "*S-1-5-32-544"],
    )
    for args in commands:
        r = subprocess.run(args, capture_output=True, text=True,
                           creationflags=_CREATE_NO_WINDOW, timeout=20)
        if r.returncode:
            raise PermissionError(f"could not protect update workspace: {r.stderr.strip()}")


def ensure_secure_update_dir() -> str:
    root = update_dir()
    if os.path.lexists(root) and _is_reparse(root):
        raise PermissionError("update workspace is a reparse point")
    os.makedirs(root, exist_ok=True)
    _harden_acl(root)
    _assert_no_reparse(root, root)
    return root


def _state_path() -> str:
    return os.path.join(update_dir(), "state.json")


def load_state() -> dict:
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict):
    root = ensure_secure_update_dir()
    tmp = os.path.join(root, f"state.{secrets.token_hex(8)}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _state_path())
    finally:
        try:
            os.remove(tmp)
        except OSError:
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
    if not tag or not _TAG_RE.fullmatch(str(tag)):
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
def _download_file(opener, url, dest, progress_cb=None, max_bytes=_MAX_ARCHIVE):
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, "Accept": "application/octet-stream"})
    with opener.open(req, timeout=120) as r:
        total = int(r.headers.get("Content-Length") or 0)
        if total > max_bytes:
            raise ValueError("update asset exceeds size limit")
        done = 0
        partial = dest + f".{secrets.token_hex(8)}.partial"
        try:
            with open(partial, "x+b") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    done += len(chunk)
                    if done > max_bytes:
                        raise ValueError("update asset exceeds size limit")
                    f.write(chunk)
                    if progress_cb:
                        progress_cb(done, total)
                f.flush()
                os.fsync(f.fileno())
            os.replace(partial, dest)
        finally:
            try:
                os.remove(partial)
            except OSError:
                pass
    return dest


def download(info: UpdateInfo, cfg: dict, progress_cb=None) -> str:
    """Download assets into a random, administrator-only transaction directory."""
    if not _TAG_RE.fullmatch(info.tag):
        raise ValueError("invalid release tag")
    opener = _opener(cfg)
    root = ensure_secure_update_dir()
    transaction_id = secrets.token_hex(16)
    ddir = os.path.join(root, transaction_id)
    os.mkdir(ddir)
    _harden_acl(ddir)
    _assert_no_reparse(ddir, root)
    # Small sidecars first (cheap, no progress), then the zip with progress.
    _download_file(opener, info.sums_url, os.path.join(ddir, "SHA256SUMS"),
                   max_bytes=_MAX_SIDECAR)
    _download_file(opener, info.sig_url, os.path.join(ddir, info.sig_name),
                   max_bytes=_MAX_SIDECAR)
    _download_file(opener, info.zip_url, os.path.join(ddir, info.zip_name), progress_cb,
                   max_bytes=_MAX_ARCHIVE)
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
        if len(parts) == 2 and parts[0].lower() == want \
                and parts[1].lstrip("*") == info.zip_name:
            return True
    return False


# ── stage (extract) + selftest gate ──────────────────────────────────────────
def _safe_member_name(name: str) -> str:
    if not name or "\x00" in name:
        raise ValueError("empty or NUL-containing archive member")
    name = name.replace("\\", "/")
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        raise ValueError("absolute archive path rejected")
    parts = [p for p in name.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise ValueError("archive traversal rejected")
    for part in parts:
        if ":" in part or part.endswith((".", " ")):
            raise ValueError("unsafe Windows archive name")
        stem = part.split(".", 1)[0].upper()
        if stem in _RESERVED_NAMES:
            raise ValueError("reserved Windows archive name")
    return os.path.join(*parts)


def _remove_tree_no_follow(path: str):
    if not os.path.lexists(path):
        return
    if _is_reparse(path):
        os.rmdir(path) if os.path.isdir(path) else os.remove(path)
        return
    shutil.rmtree(path)


def stage(info: UpdateInfo, ddir: str) -> str:
    """Safely extract a verified archive into its protected transaction."""
    root = ensure_secure_update_dir()
    _assert_no_reparse(ddir, root)
    staged = os.path.join(ddir, "staged")
    _remove_tree_no_follow(staged)
    os.mkdir(staged)
    _harden_acl(staged)
    seen = set()
    expanded = 0
    with zipfile.ZipFile(os.path.join(ddir, info.zip_name)) as z:
        members = z.infolist()
        if len(members) > _MAX_MEMBERS:
            raise ValueError("archive contains too many members")
        for zi in members:
            rel = _safe_member_name(zi.filename)
            folded = rel.casefold()
            if folded in seen:
                raise ValueError("duplicate archive member")
            seen.add(folded)
            expanded += zi.file_size
            if expanded > _MAX_EXTRACTED:
                raise ValueError("archive expansion exceeds limit")
            # Unix symlinks are encoded in the high mode bits.
            if stat.S_ISLNK((zi.external_attr >> 16) & 0xFFFF):
                raise ValueError("archive link rejected")
            dest = os.path.join(staged, rel)
            _assert_beneath(dest, staged)
            if zi.is_dir():
                os.makedirs(dest, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with z.open(zi) as src, open(dest, "xb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
    if not os.path.isfile(os.path.join(staged, "ProxyForce.exe")) \
            or not os.path.isdir(os.path.join(staged, "_internal")):
        raise ValueError("archive does not contain the expected application layout")
    return staged


def transaction_id(ddir: str) -> str:
    root = ensure_secure_update_dir()
    _assert_no_reparse(ddir, root)
    if os.path.dirname(os.path.abspath(ddir)) != os.path.abspath(root):
        raise ValueError("invalid transaction directory")
    return os.path.basename(ddir)


def transaction_dir(txid: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", txid or ""):
        raise ValueError("invalid update transaction")
    root = ensure_secure_update_dir()
    path = os.path.join(root, txid)
    _assert_no_reparse(path, root)
    return path


def prepare_apply(info: UpdateInfo, txid: str, install_dir: str) -> str:
    """Reverify and freshly extract immediately before elevated execution."""
    ddir = transaction_dir(txid)
    if not verify(info, ddir):
        raise ValueError("staged update failed final signature verification")
    staged = stage(info, ddir)
    meta = {
        "tag": info.tag,
        "archive_sha256": _sha256(os.path.join(ddir, info.zip_name)),
        "target": os.path.abspath(install_dir),
        "apply_token": secrets.token_hex(32),
    }
    meta_path = os.path.join(ddir, "transaction.json")
    with open(meta_path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(meta, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(meta_path + ".tmp", meta_path)
    return staged


def mark_update_ready(txid: str):
    """Positive readiness signal emitted by the freshly launched GUI."""
    path = os.path.join(transaction_dir(txid), "ready")
    with open(path, "x", encoding="ascii") as f:
        f.write(APP_VERSION)


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
def begin_apply(staged: str, install_dir: str, wait_pid: int):
    """Spawn the staged build's exe as a detached, elevated worker that waits for
    this process (wait_pid) to exit, swaps the install folder, and relaunches. The
    caller must then stop the proxy and exit promptly.

    The relaunch is always `--minimized` (resume-after-update is driven by
    state.json, not args), so there is no relaunch-args parameter to thread through."""
    root = ensure_secure_update_dir()
    txdir = os.path.dirname(os.path.abspath(staged))
    _assert_no_reparse(staged, root)
    if os.path.dirname(txdir) != os.path.abspath(root):
        raise ValueError("staged worker is outside the protected workspace")
    exe = os.path.join(staged, "ProxyForce.exe")
    meta_path = os.path.join(os.path.dirname(staged), "transaction.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    if os.path.normcase(meta.get("target", "")) != os.path.normcase(os.path.abspath(install_dir)):
        raise ValueError("update target does not match protected transaction")
    token = meta.get("apply_token")
    if not re.fullmatch(r"[0-9a-f]{64}", token or ""):
        raise ValueError("invalid apply token")
    # Relaunch is always "--minimized" (resume-after-update is driven by state.json,
    # not args) — so we don't pass an arg value that itself starts with "--".
    args = [exe, "--apply-update", "--target", install_dir, "--wait-pid", str(wait_pid),
            "--apply-token", token]
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


def _kill_image(name: str):
    """Force-kill every process with this image name (best-effort)."""
    try:
        subprocess.run(["taskkill", "/F", "/IM", name],
                       capture_output=True, creationflags=_CREATE_NO_WINDOW, timeout=15)
    except Exception:
        pass


def _procs_under(prefix_norm: str, exclude_pid: int):
    """PIDs of running processes whose executable image lives under `prefix_norm`
    (a normcased absolute path ending in os.sep), excluding `exclude_pid`. Used to
    find anything still running FROM the install dir we are about to rename."""
    ps = ("Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath} | "
          "ForEach-Object { \"$($_.ProcessId)|$($_.ExecutablePath)\" }")
    pids = []
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True,
                           creationflags=_CREATE_NO_WINDOW, timeout=20)
        for line in (r.stdout or "").splitlines():
            pid_s, sep, path = line.strip().partition("|")
            if not sep or not path.strip():
                continue
            try:
                pid = int(pid_s.strip())
            except ValueError:
                continue
            if pid != exclude_pid and os.path.normcase(path.strip()).startswith(prefix_norm):
                pids.append(pid)
    except Exception:
        pass
    return pids


def _free_install_dir(target: str, timeout: float = 30.0) -> bool:
    """Guarantee nothing is locking the install dir before we rename it — the fix for
    the swap's PermissionError(13) 'being used by another process'.

    On Windows a directory cannot be renamed while ANY process has a file open in it
    OR has its current directory inside it. Two things run FROM the install tree and
    cause exactly that error during a self-update swap:
      * sing-box.exe — ProxyForce launches it with its CWD inside _internal\\singbox\\,
        so it pins the whole dir even mid-teardown. Force-kill it: it is stateless and
        the relaunched build restarts it.
      * the outgoing GUI ProxyForce.exe — if it is slow to fully exit after stop()
        (lingering threads), or is an orphan from a crashed/rolled-back run, it keeps
        ProxyForce.exe + the _internal DLLs mapped.
    The worker itself runs from the STAGED dir (never under target), so it is never a
    target here. Kill sing-box, then kill/await any ProxyForce-under-target until the
    dir is clear or we time out."""
    me = os.getpid()
    prefix = os.path.normcase(os.path.abspath(target)).rstrip("\\/") + os.sep
    _kill_image("sing-box.exe")
    deadline = time.time() + timeout
    while True:
        lockers = _procs_under(prefix, exclude_pid=me)
        if not lockers:
            return True
        _applog(f"install dir locked by pids {lockers} — killing before swap")
        for pid in lockers:
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, creationflags=_CREATE_NO_WINDOW, timeout=10)
            except Exception:
                pass
        if time.time() >= deadline:
            return False
        time.sleep(1.5)


def apply_worker(argv):
    """The `--apply-update` worker. Runs from the staged copy with the install dir
    free to overwrite. Waits for the outgoing process to exit, frees the install dir
    of any straggler (sing-box / a slow-exiting or orphaned GUI) that would block the
    directory rename, then swaps."""
    opts = _parse_kv(argv)
    target = opts.get("target")
    wait_pid = int(opts.get("wait-pid") or 0)
    staged = os.path.dirname(os.path.abspath(sys.executable))
    if not opts.get("apply-token"):
        return _bridge_legacy_apply(staged, target, wait_pid)
    valid = _validate_apply_transaction(staged, target, opts.get("apply-token"))
    if not valid:
        _applog("apply rejected: protected transaction validation failed")
        return False
    _applog(f"apply start: target={target} staged={staged} wait_pid={wait_pid}")
    _wait_pid_exit(wait_pid, timeout=120)
    freed = _free_install_dir(target)
    _applog(f"install dir freed={freed}")
    time.sleep(1.0)                             # let handles/AV release
    return _apply_swap(staged, target, "--minimized")


def _bridge_legacy_apply(staged: str, target: str, wait_pid: int) -> bool:
    """Bootstrap a pre-v2 updater invocation into a protected v2 transaction.

    v2.1.15 and older launch the downloaded build without an apply token. The new
    executable is already running at this point, so it must not swap from the legacy,
    user-writable tree. Instead, copy the signed assets into update-v2, verify them
    there, freshly extract, and hand off to the normal token-protected worker.
    """
    legacy_root = os.path.abspath(_legacy_update_dir())
    ddir = os.path.dirname(os.path.abspath(staged))
    tag = os.path.basename(ddir)
    if (os.path.normcase(os.path.dirname(ddir)) != os.path.normcase(legacy_root)
            or os.path.basename(staged).casefold() != "staged"
            or not _TAG_RE.fullmatch(tag)
            or tag.lstrip("vV") != APP_VERSION
            or not target
            or not os.path.isfile(os.path.join(os.path.abspath(target), "ProxyForce.exe"))):
        _applog("legacy apply rejected: invocation is not a valid updater bootstrap")
        return False

    info = UpdateInfo(tag, False, "", "", "")
    _wait_pid_exit(wait_pid, timeout=120)
    try:
        root = ensure_secure_update_dir()
        txid = secrets.token_hex(16)
        secure_dir = os.path.join(root, txid)
        os.mkdir(secure_dir)
        _harden_acl(secure_dir)
        for name in ("SHA256SUMS", info.sig_name, info.zip_name):
            src = os.path.join(ddir, name)
            dst = os.path.join(secure_dir, name)
            if not os.path.isfile(src):
                raise ValueError(f"legacy update asset missing: {name}")
            with open(src, "rb") as inp, open(dst, "xb") as out:
                shutil.copyfileobj(inp, out, 1 << 20)
        if not verify(info, secure_dir):
            raise ValueError("legacy update failed signature verification after import")

        # Preserve only continuity state; never import a path from the legacy file.
        legacy_state = {}
        try:
            with open(os.path.join(legacy_root, "state.json"), "r", encoding="utf-8") as f:
                legacy_state = json.load(f)
        except Exception:
            pass
        save_state({
            "staged_tag": tag,
            "staged_version": info.version,
            "transaction_id": txid,
            "resume_proxy": bool(legacy_state.get("resume_proxy")),
            "last_check_date": legacy_state.get("last_check_date"),
        })
        protected_stage = prepare_apply(info, txid, os.path.abspath(target))
        if not selftest_staged(protected_stage):
            raise ValueError("protected bootstrap build failed selftest")
        begin_apply(protected_stage, os.path.abspath(target), os.getpid())
        _applog(f"legacy apply bridged into protected transaction {txid}")
        return True
    except Exception as e:
        _applog(f"legacy apply bridge FAILED: {e!r}")
        return False


def _validate_apply_transaction(staged: str, target: str, token: str) -> bool:
    meta_path = os.path.join(os.path.dirname(staged), "transaction.json")
    try:
        root = ensure_secure_update_dir()
        txdir = os.path.dirname(os.path.abspath(staged))
        _assert_no_reparse(staged, root)
        if os.path.dirname(txdir) != os.path.abspath(root):
            return False
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return bool(
            re.fullmatch(r"[0-9a-f]{64}", token or "")
            and secrets.compare_digest(token, meta.get("apply_token", ""))
            and os.path.normcase(os.path.abspath(target or ""))
            == os.path.normcase(meta.get("target", ""))
            and os.path.normcase(os.path.dirname(meta_path)) == os.path.normcase(txdir)
        )
    except Exception:
        return False


def _rollback_to_backup(target: str, backup: str, target_exe: str, relaunch: str):
    """Discard whatever landed in `target` (even a partial copy) and restore the
    pre-update `backup`, then relaunch whichever build ends up there.

    The build we just relaunched into `target` (however broken) may already have
    auto-started sing-box.exe — or still be mid-exit itself — by the time the
    health check fails, locking exactly the files this needs to replace. A bare
    rmtree+rename (the old behaviour) silently swallowed that: rmtree(ignore_errors)
    left `target` half-deleted, the rename onto a non-empty directory then failed
    and was only logged, so the box was left with a broken `target` AND an orphaned
    `backup` (.old) — the worst of both states. Retry the cheap path first, escalate
    to freeing the dir (same as the forward swap) if that fails, and fall back to a
    file-level copy if the rename still can't land."""
    def _clear_target():
        if os.path.isdir(target):
            shutil.rmtree(target)

    try:
        _clear_target()
        os.rename(backup, target)
    except Exception as e:
        _applog(f"rollback rmtree/rename failed: {e!r} — freeing install dir and retrying")
        _free_install_dir(target)
        try:
            _retry(_clear_target, tries=10, delay=1.0)
            _retry(lambda: os.rename(backup, target), tries=10, delay=1.0)
        except Exception as e2:
            _applog(f"rollback retry failed: {e2!r} — falling back to file-level restore")
            try:
                _retry(lambda: shutil.copytree(backup, target, dirs_exist_ok=True),
                       tries=5, delay=1.0)
                shutil.rmtree(backup, ignore_errors=True)
            except Exception as e3:
                _applog(f"rollback file-level restore also failed: {e3!r} — target may "
                        f"still be broken, backup preserved at {backup}")
    if os.path.isfile(target_exe):
        _spawn(target_exe, relaunch)


def _apply_swap(staged: str, target: str, relaunch: str) -> bool:
    """Back up the install dir, copy the staged build in, relaunch it, and roll back
    if the copy is incomplete or the new build doesn't stay up. Returns True on a
    committed, healthy swap."""
    target_exe = os.path.join(target, "ProxyForce.exe")
    backup = target.rstrip("\\/") + ".old"

    try:
        if os.path.isdir(backup):
            shutil.rmtree(backup, ignore_errors=True)
        _retry(lambda: os.rename(target, backup), tries=20)   # move old aside
        # dirs_exist_ok so a retry after a partial copy doesn't trip FileExistsError.
        _retry(lambda: shutil.copytree(staged, target, dirs_exist_ok=True))  # install new
        # copytree can raise after copying MOST files (e.g. AV real-time scanning
        # transiently locks/quarantines the freshly-written sing-box.exe) and still
        # leave `target` populated with everything else. A missing engine binary is
        # just as broken as a missing exe, so catch it here — otherwise it slips past
        # the rollback check below (target DOES exist, just incompletely) and a
        # half-installed build gets relaunched instead of rolled back.
        if not os.path.isfile(os.path.join(target, "_internal", "singbox", "sing-box.exe")):
            raise RuntimeError("copy incomplete: sing-box.exe missing from installed build")
        _applog("swap ok")
    except Exception as e:
        _applog(f"swap FAILED: {e!r} — rolling back")
        if os.path.isdir(backup):
            _rollback_to_backup(target, backup, target_exe, relaunch)
        elif os.path.isfile(target_exe):
            _spawn(target_exe, relaunch)
        return False

    # Relaunch the new build (elevated child of this elevated worker → no UAC).
    try:
        proc = _spawn(target_exe, relaunch)
    except Exception as e:
        _applog(f"relaunch spawn failed: {e!r} — rolling back")
        proc = None

    # Health check: the new build must stay alive and emit a positive ready marker.
    healthy = False
    ready_path = os.path.join(os.path.dirname(staged), "ready")
    if proc is not None:
        for _ in range(_HEALTH_CHECKS):
            if proc.poll() is not None:
                break
            if os.path.isfile(ready_path):
                healthy = True
                break
            time.sleep(_HEALTH_INTERVAL)

    if not healthy:
        _applog("new build did not stay up — rolling back to .old")
        _rollback_to_backup(target, backup, target_exe, relaunch)
        return False

    # Success: drop the backup. The staged dir (this worker's own folder) is removed
    # by the freshly-launched instance via cleanup_staging() once we exit. A stray
    # handle (e.g. AV briefly scanning the .old tree) can make a single rmtree
    # attempt leave remnants behind — retry before giving up, since a lingering
    # .old folder after an otherwise-healthy update is just confusing clutter, not
    # a failure, but should still be cleaned up whenever possible.
    try:
        _retry(lambda: shutil.rmtree(backup) if os.path.isdir(backup) else None,
               tries=5, delay=1.0)
    except Exception as e:
        _applog(f"backup cleanup failed (non-fatal, update still succeeded): {e!r}")
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
            try:
                _remove_tree_no_follow(path)
            except OSError:
                pass


def migrate_legacy_update_state():
    """Invalidate pre-hardening state and remove legacy staging without following links."""
    ensure_secure_update_dir()
    legacy = _legacy_update_dir()
    if not os.path.lexists(legacy):
        return
    # Preserve only benign runtime continuity. Never import legacy paths or pending
    # update identity from the user-writable v1 workspace.
    try:
        with open(os.path.join(legacy, "state.json"), "r", encoding="utf-8") as f:
            old_state = json.load(f)
        state = load_state()
        for key in ("resume_proxy", "last_check_date"):
            if key in old_state and key not in state:
                state[key] = old_state[key]
        if state:
            save_state(state)
    except Exception:
        pass
    try:
        _remove_tree_no_follow(legacy)
    except OSError:
        # A locked old worker may still be exiting; leaving it is safer than following it.
        pass
