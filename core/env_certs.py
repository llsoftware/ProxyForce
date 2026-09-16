"""
ProxyForce — CA-trust environment variables (the TLS-inspection fix).

WHY THIS EXISTS (TLS-inspection report, 2026-09-15):
  On a network that does TLS inspection, the certificate an app sees is minted by
  the inspection appliance's CA, not by the origin's. ProxyForce itself never
  terminates TLS — it issues `CONNECT host:443` and shovels bytes — so it neither
  causes nor can route around this: the app must simply TRUST the inspection CA.

  Windows' own trust store usually already has it (pushed by GPO), which is why
  browsers and Office are fine. But a large class of CLI/dev tools does NOT read
  the Windows store — each ships its own baked-in CA bundle:

      docker, pip, requests, curl, git (openssl backend), node, Go, cargo, aws-cli

  ...so they reject the inspected handshake with an "unable to get local issuer
  certificate" / "self-signed certificate in certificate chain" error while every
  GUI app on the same box works. This is the EXACT same blind spot that
  core/env_proxy exists for (those tools ignore the registry proxy for the same
  reason they ignore the registry trust store) — so it is fixed the same way, in
  the same lane, with the same snapshot/restore discipline.

WHY WE MERGE RATHER THAN EXPORT THE WINDOWS STORE:
  The obvious implementation — dump LocalMachine\\Root to a PEM and point the
  tools at it — is actively DANGEROUS, and measurably so. Windows ships only a
  small seed set of roots and pulls the rest on demand (Automatic Root Update),
  so the live store is a SUBSET of the public trust list. Measured on the machine
  this was written against:

      ssl.enum_certificates("ROOT")     ->   36 certs
      Mozilla/curl ca-bundle.crt        ->  150 certs

  Pointing SSL_CERT_FILE at those 36 would have REVOKED trust for ~114 public CAs
  — turning a narrow corporate-TLS failure into a broad one. So the emitted bundle
  is a UNION, deduplicated by certificate fingerprint:

      assets/ca/mozilla-cacert.pem   (shipped, complete public trust baseline)
    + ssl.enum_certificates("ROOT")  (live Windows store -> picks up whatever else
                                      GPO pushed, no config needed)
    + the configured corporate CA    (optional; assets/ca/corporate-ca.pem, or a
                                      path the user picked in Settings)

  Fail-closed: if the merge produces nothing usable, the environment variables are
  NOT written. A variable pointing at a missing or empty bundle breaks TLS for
  every tool that reads it, which is far worse than the problem being fixed.

TWO OUTPUT FILES, BECAUSE THE VARIABLES HAVE TWO DIFFERENT SEMANTICS:
  * ca-bundle.pem    — the full merged union. Every var in _BUNDLE_VARS REPLACES
                       the tool's own bundle with this file, so it must be
                       complete.
  * ca-corporate.pem — the PRIVATE roots only: the configured corporate CA plus
                       every Windows root that is not part of public trust.
                       NODE_EXTRA_CA_CERTS *extends* Node's built-in list rather
                       than replacing it, so it wants the extras alone.

NOTES:
  * The shipped corporate certificate is OPTIONAL and is deliberately NOT
    committed: the repository is public and the certificate identifies the
    organisation's inspection appliance. A build from a clean clone therefore has
    no assets/ca/corporate-ca.pem, and must still work -- which it does, because
    the live Windows ROOT store is merged in regardless and is where a GPO-managed
    machine already has that CA. Only a path the USER configured is treated as
    mandatory (a typo there must fail loudly, not be silently ignored).
  * Opt-in. Off unless `ca_inject` is enabled in config_store — silently
    repointing a machine's trust configuration is not something a proxy tool
    should do uninvited.
  * Java is NOT handled here: the JDK reads its own `cacerts` keystore and has no
    env-var override, so it needs `keytool -importcert` per JDK. That lives in
    core/java_trust, which the controller calls right after this module.
  * Anything running INSIDE a container sees neither the Windows store nor these
    variables. `docker pull` (daemon -> registry) is fixed from the host; a
    `RUN pip install` inside a build is not, and cannot be by any host-side tool.
  * Environment variables are read at CreateProcess time — already-open shells must
    be reopened. Same caveat as core/env_proxy; the caller logs it.
  * Crash-safe like core/env_proxy and core/system_proxy: the snapshot is written to
    disk before the first overwrite, so a crashed run is undone on next start.
"""

import os
import re
import ssl
import sys
import json
import base64
import hashlib
import ctypes
import winreg
import subprocess

_USER_KEY = r"Environment"
_MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

# Vars whose value REPLACES the tool's own CA bundle -> must point at the full union.
# Deliberately broad: every one of these is a real, documented override for a
# runtime that ignores the Windows trust store, and setting one for a toolchain
# that is not installed costs nothing. Docker was only the reported symptom — the
# same inspection CA breaks every entry below.
_BUNDLE_VARS = (
    "SSL_CERT_FILE",        # OpenSSL, Python ssl/urllib, Go, Ruby, PHP curl
    "REQUESTS_CA_BUNDLE",   # python-requests (conda, azure-cli, many SDKs)
    "CURL_CA_BUNDLE",       # curl (requests honours it too)
    "GIT_SSL_CAINFO",       # git with the openssl backend (schannel ignores it)
    "PIP_CERT",             # pip
    "AWS_CA_BUNDLE",        # aws-cli / boto3
    "CARGO_HTTP_CAINFO",    # cargo / rustup
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",  # gRPC C core (gcloud, many SDKs)
    "HTTPLIB2_CA_CERTS",    # httplib2 (older google-api clients)
    "DENO_CERT",            # deno
    "NIX_SSL_CERT_FILE",    # nix
    "PERL_LWP_SSL_CA_FILE",  # perl LWP
)
# Vars whose value is ADDED to the tool's built-in roots -> corporate CA only.
_EXTRA_VARS = (
    "NODE_EXTRA_CA_CERTS",  # node, and npm/yarn/pnpm through it
)
_ALL_VAR_NAMES = _BUNDLE_VARS + _EXTRA_VARS

_HIVES = {"user": winreg.HKEY_CURRENT_USER, "machine": winreg.HKEY_LOCAL_MACHINE}
_SUBKEYS = {"user": _USER_KEY, "machine": _MACHINE_KEY}

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)

# Below this many live Windows roots, the store is its usual sparse self and is
# not a safe standalone source for a replace-semantics bundle (see module notes).
_MIN_STANDALONE_ROOTS = 40


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "env_certs_backup.json")


def bundle_path() -> str:
    """The merged union bundle written by apply()."""
    return os.path.join(_data_dir(), "ca-bundle.pem")


def corporate_path() -> str:
    """The corporate-CA-only file written by apply() (for NODE_EXTRA_CA_CERTS)."""
    return os.path.join(_data_dir(), "ca-corporate.pem")


# ── shipped assets ────────────────────────────────────────────────────────────

def _asset(name: str) -> str:
    """Resolve a shipped CA asset across frozen-onedir and source layouts
    (mirrors _find_singbox_exe in core/singbox_controller)."""
    candidates = []
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        candidates.append(os.path.join(mei, "ca", name))
    if getattr(sys, "frozen", False):
        exedir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exedir, "_internal", "ca", name))
        candidates.append(os.path.join(exedir, "ca", name))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.normpath(
        os.path.join(here, "..", "assets", "ca", name)))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return ""


def shipped_corporate_ca() -> str:
    """Path to the corporate inspection CA ProxyForce ships with (replaceable —
    see `ca_cert_path` in config_store)."""
    return _asset("corporate-ca.pem")


def base_bundle() -> str:
    """Path to the shipped complete public-trust baseline."""
    return _asset("mozilla-cacert.pem")


# ── PEM handling ──────────────────────────────────────────────────────────────

def _read_pem_ders(path: str) -> list:
    """Extract every certificate in a PEM file as DER bytes. Tolerates comments,
    CRLF, and multiple concatenated certs (a user-supplied file often has all
    three). Returns [] if the file is unreadable or holds no certificates."""
    if not path:
        return []
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return []
    ders = []
    for m in _PEM_RE.finditer(raw):
        body = re.sub(rb"\s+", b"", m.group(1))
        try:
            ders.append(base64.b64decode(body, validate=True))
        except Exception:
            continue    # a malformed block must not discard the valid ones
    return ders


def _windows_root_ders() -> list:
    """The live Windows ROOT store, filtered to certs trusted for server auth.
    This is what makes a GPO-pushed corporate CA work with no configuration."""
    server_auth = "1.3.6.1.5.5.7.3.1"
    ders = []
    try:
        for cert, enc, trust in ssl.enum_certificates("ROOT"):
            if enc != "x509_asn":
                continue
            # trust is True (valid for all purposes) or a set of EKU OIDs.
            if trust is True or trust is None or server_auth in (trust or ()):
                ders.append(cert)
    except Exception:
        pass
    return ders


def _fp(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def _ascii(s: str) -> str:
    """Force a comment line to plain ASCII. The PEM body is base64 by definition,
    but the header quotes the certificate's subject — which can legitimately hold
    non-Latin characters (or an em-dash from our own wording) and would otherwise
    raise on the ascii-encoded write."""
    return (s.replace("—", "-").replace("–", "-")
             .encode("ascii", "replace").decode("ascii"))


def _write_atomic(path: str, text: str):
    """Write via temp+replace so a tool reading the bundle concurrently never sees
    a half-written file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="ascii", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


# ── cert inspection (for the GUI / log) ───────────────────────────────────────

def describe_cert_file(path: str) -> tuple:
    """(ok, summary) for a candidate CA file — used to validate a replacement
    certificate BEFORE it is trusted machine-wide.

    Validation is real, not cosmetic: the file is handed to OpenSSL via
    load_verify_locations, so a PEM that merely *looks* right but does not parse
    is rejected here rather than silently producing an unusable bundle."""
    if not path:
        return False, "No certificate file configured."
    if not os.path.isfile(path):
        return False, f"File not found: {path}"
    ders = _read_pem_ders(path)
    if not ders:
        return False, ("No PEM certificate found. Export the CA as Base-64 "
                       "(.cer/.crt/.pem), not DER/binary.")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cafile=path)
    except Exception as e:
        return False, f"Not a valid PEM certificate file: {e}"
    names = _subject_names(path)
    if names:
        label = ", ".join(names[:3]) + ("..." if len(names) > 3 else "")
    else:
        label = ", ".join(_fp(d)[:16] for d in ders[:3])
    n = len(ders)
    return True, f"{n} certificate{'s' if n != 1 else ''}: {label}"


def _subject_names(path: str) -> list:
    """Best-effort human-readable subject CNs via certutil (always present on
    Windows). Never raises — the caller falls back to fingerprints."""
    try:
        r = subprocess.run(["certutil", "-dump", path], capture_output=True,
                           text=True, creationflags=_NO_WINDOW, timeout=15)
        out = r.stdout or ""
    except Exception:
        return []
    names = []
    for m in re.finditer(r"CN=([^,\r\n]+)", out):
        val = m.group(1).strip()
        if val and val not in names:
            names.append(val)
    return names


# ── bundle construction ───────────────────────────────────────────────────────

def build_bundle(corporate_ca: str = "") -> dict:
    """Merge the shipped baseline, the live Windows ROOT store, and the corporate
    CA into ca-bundle.pem (+ ca-corporate.pem). Returns a stats dict:

        {"ok": bool, "error": str, "total": int, "base": int, "windows": int,
         "corporate": int, "cert_path": str, "cert_summary": str,
         "bundle": path, "corporate_file": path}

    `corporate_ca` defaults to the shipped certificate when empty, and the
    shipped certificate is OPTIONAL — see the note on sourcing below."""
    stats = {"ok": False, "error": "", "total": 0, "base": 0, "windows": 0,
             "corporate": 0, "extras": 0, "cert_path": "", "cert_summary": "",
             "bundle": bundle_path(), "corporate_file": corporate_path()}

    # Where the corporate CA comes from, in order of authority:
    #   1. a path the user configured  -> MUST be valid; a typo must not be
    #      silently ignored, or they would believe a CA is trusted that is not.
    #   2. the certificate shipped in assets/ca  -> optional. It is deliberately
    #      NOT committed (the repository is public and the certificate identifies
    #      the organisation's inspection appliance), so a build made from a clean
    #      clone has no such file and must still work.
    #   3. the live Windows ROOT store -> on a GPO-managed machine the inspection
    #      CA is already there, which is why browsers work. It is merged in below
    #      regardless, so case 2 is genuinely optional rather than a silent
    #      degradation.
    explicit = bool(corporate_ca)
    corp_path = corporate_ca or shipped_corporate_ca()
    stats["cert_path"] = corp_path
    if corp_path:
        ok, summary = describe_cert_file(corp_path)
        stats["cert_summary"] = summary
        if not ok:
            if explicit:
                stats["error"] = f"corporate CA unusable — {summary}"
                return stats
            corp_path = ""      # shipped asset broken -> fall through to the store
            stats["cert_path"] = ""
            stats["cert_summary"] = (
                f"shipped certificate unusable ({summary}); "
                f"relying on the Windows trust store instead")
    else:
        stats["cert_summary"] = ("no certificate file configured; taking the "
                                 "inspection CA from the Windows trust store")
    corp_ders = _read_pem_ders(corp_path) if corp_path else []

    base_ders = _read_pem_ders(base_bundle())
    win_ders = _windows_root_ders()

    if not base_ders and len(win_ders) < _MIN_STANDALONE_ROOTS:
        # Shipped baseline missing AND the live store is its usual sparse self:
        # emitting this would strip trust for most public CAs. Refuse outright.
        stats["error"] = (
            f"refusing to build a bundle from {len(win_ders)} Windows roots alone "
            f"(the shipped public-trust baseline is missing) — it would remove "
            f"trust for most public CAs")
        return stats

    seen = set()
    out = []
    # Corporate first so it is easy to find when eyeballing the file.
    for label, ders in (("corporate", corp_ders), ("base", base_ders),
                        ("windows", win_ders)):
        added = 0
        for d in ders:
            f = _fp(d)
            if f in seen:
                continue
            seen.add(f)
            out.append(d)
            added += 1
        stats[label] = added

    if not out:
        stats["error"] = "no certificates to write"
        return stats

    # The NODE_EXTRA_CA_CERTS file: certificates that are NOT part of public
    # trust, since Node extends its built-in roots rather than replacing them.
    # Taking "everything in the Windows store that the public baseline does not
    # have" is what makes the shipped certificate optional — on a GPO-managed
    # machine that set IS the corporate CA (plus any other private root the
    # organisation pushed), so Node is fixed with or without assets/ca.
    baseline_fps = {_fp(d) for d in base_ders}
    extras, extra_seen = [], set()
    for d in corp_ders + win_ders:
        f = _fp(d)
        if f in baseline_fps or f in extra_seen:
            continue
        extra_seen.add(f)
        extras.append(d)
    stats["extras"] = len(extras)

    header = _ascii(
        "# ProxyForce merged CA bundle - generated, do not edit.\n"
        "# Sources: shipped public-trust baseline + live Windows ROOT store"
        " + corporate CA.\n"
        f"# Corporate CA: {corp_path or '(none - taken from the Windows store)'}\n"
        f"# {stats['cert_summary']}\n")
    try:
        _write_atomic(bundle_path(), header + "".join(_to_pem(d) for d in out))
        _write_atomic(corporate_path(),
                      _ascii("# ProxyForce private/corporate CAs only "
                             "(NODE_EXTRA_CA_CERTS): every root trusted by this\n"
                             "# machine that is not part of public trust.\n"
                             f"# {stats['cert_summary']}\n")
                      + "".join(_to_pem(d) for d in extras))
    except OSError as e:
        stats["error"] = f"could not write the bundle: {e}"
        return stats

    stats["total"] = len(out)
    stats["ok"] = True
    return stats


# ── snapshot / set / restore (mirrors core/env_proxy) ─────────────────────────

def _snapshot() -> dict:
    snap = {}
    for scope, hive in _HIVES.items():
        entry = {}
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope]) as k:
                for name in _ALL_VAR_NAMES:
                    try:
                        val, typ = winreg.QueryValueEx(k, name)
                        entry[name] = [val, typ]
                    except FileNotFoundError:
                        entry[name] = None
        except OSError:
            entry = {name: None for name in _ALL_VAR_NAMES}
        snap[scope] = entry
    return snap


def _describe(snap: dict) -> str:
    parts = []
    for scope in ("user", "machine"):
        for name in _ALL_VAR_NAMES:
            entry = (snap.get(scope) or {}).get(name)
            if entry is not None and entry[0]:
                parts.append(f"{scope}:{name}={entry[0]}")
    return ", ".join(parts)


def _set(bundle: str, corporate: str):
    """Write every CA variable into both the machine and the current user's
    environment. Unlike env_proxy there is no 'delete when empty' branch: both
    paths are always non-empty by the time apply() calls this (it fails closed
    before reaching here), and a half-written group is the failure mode that
    breaks TLS."""
    values = {name: bundle for name in _BUNDLE_VARS}
    values.update({name: corporate for name in _EXTRA_VARS})
    for scope, hive in _HIVES.items():
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope], 0, winreg.KEY_SET_VALUE) as k:
                for name, val in values.items():
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
        except OSError:
            pass
    _broadcast()


def _restore(snap: dict):
    for scope, hive in _HIVES.items():
        entry = snap.get(scope) or {}
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope], 0, winreg.KEY_SET_VALUE) as k:
                for name in _ALL_VAR_NAMES:
                    stored = entry.get(name)
                    if stored is None:
                        try:
                            winreg.DeleteValue(k, name)
                        except FileNotFoundError:
                            pass
                    else:
                        val, typ = stored
                        winreg.SetValueEx(k, name, 0, typ, val)
        except OSError:
            pass
    _broadcast()


def _broadcast():
    """Tell running apps the environment changed (WM_SETTINGCHANGE). Best-effort:
    most CLI tools read the environment once at process start, so a shell must be
    reopened to pick this up."""
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 1000, ctypes.byref(result))
    except Exception:
        pass


def _write_backup(snap: dict):
    try:
        os.makedirs(_data_dir(), exist_ok=True)
        with open(_backup_path(), "w", encoding="utf-8") as f:
            json.dump(snap, f)
    except Exception:
        pass


def _read_backup():
    try:
        with open(_backup_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _clear_backup():
    try:
        os.remove(_backup_path())
    except OSError:
        pass


# ── public API ────────────────────────────────────────────────────────────────

def apply(corporate_ca: str = "") -> dict:
    """Build the merged bundle, then point the CA-bundle environment variables at
    it (machine + user hives, crash-safe snapshot first).

    FAIL-CLOSED: if the bundle cannot be built, NOTHING is written to the
    environment — a variable pointing at a missing bundle would break TLS for
    every tool that reads it, which is strictly worse than the inspection error
    being fixed.

    Idempotent/crash-safe like env_proxy.point_at: if a backup already exists (a
    prior run set these and never restored), that backup is kept as the true
    original. Returns build_bundle()'s stats dict plus a "previous" key
    describing any CA vars that were already set (for the log)."""
    stats = build_bundle(corporate_ca)
    stats["previous"] = ""
    if not stats["ok"]:
        return stats
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        stats["previous"] = _describe(snap)
    _set(bundle_path(), corporate_path())
    return stats


def restore() -> bool:
    """Restore the snapshotted CA variables. Idempotent: no backup -> no-op.
    The generated bundle files are left on disk deliberately — they are inert
    once nothing points at them, and stay useful for a manual `curl --cacert`."""
    snap = _read_backup()
    if snap is None:
        return False
    _restore(snap)
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current CA-variable state (for diagnostics)."""
    snap = _snapshot()
    parts = []
    for scope in ("user", "machine"):
        entry = snap.get(scope) or {}
        set_vars = [f"{n}={entry[n][0]}" for n in _ALL_VAR_NAMES
                    if entry.get(n) is not None and entry[n][0]]
        parts.append(f"{scope}: " + (", ".join(set_vars) if set_vars else "(none set)"))
    return "  ||  ".join(parts)
