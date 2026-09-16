"""
ProxyForce — Java truststore import (the half core/env_certs cannot reach).

WHY A SEPARATE MODULE:
  Every runtime handled by core/env_certs has an environment variable that
  overrides its CA bundle. Java does not. The JVM reads a *keystore* —
  `<java-home>/lib/security/cacerts`, a PKCS12/JKS binary — and there is no
  supported env var that points it at a PEM. `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.
  trustStore=...` exists but replaces the whole truststore (so the JVM loses every
  public CA unless we rebuild them all), applies to every JVM on the box including
  ones we know nothing about, and makes the JVM print a banner to stderr that
  breaks scripts parsing Java output. So the correct fix is the documented one:
  import the corporate CA into each keystore with `keytool`.

  That is a real mutation of an installed JDK, so it gets the same discipline as
  every other takeover in this codebase (core/system_proxy, core/env_proxy,
  core/appcontainer): record exactly what was changed to a ProgramData backup file
  BEFORE changing it, and undo exactly that on stop — including after a crash.
  Because we only ever ADD aliases under our own prefix, the undo is precise: we
  delete the aliases we created and touch nothing else. A pre-existing alias of the
  same name is left alone and never deleted (it was not ours to remove).

SCOPE:
  Best-effort by design. A JDK with a non-default keystore password, a
  read-only/managed install, or a keytool that refuses is logged and skipped — it
  must never fail the connect. Java is usually a minority of a machine's TLS
  traffic; the env-var side (core/env_certs) is the load-bearing half.
"""

import os
import re
import glob
import json
import base64
import hashlib
import subprocess

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Every alias we create starts with this, so restore() can identify its own work
# and never deletes an alias that was already there.
_ALIAS_PREFIX = "proxyforce-corporate-ca"
_DEFAULT_STOREPASS = "changeit"     # the JDK default; unchanged on most installs

# Where JDKs/JREs live on Windows. Globbed, so multiple installed versions are all
# covered — a dev box commonly has several and builds pick between them.
_SEARCH_GLOBS = (
    r"C:\Program Files\Java\*",
    r"C:\Program Files (x86)\Java\*",
    r"C:\Program Files\Eclipse Adoptium\*",
    r"C:\Program Files\Eclipse Foundation\*",
    r"C:\Program Files\Microsoft\jdk*",
    r"C:\Program Files\Amazon Corretto\*",
    r"C:\Program Files\Zulu\*",
    r"C:\Program Files\BellSoft\*",
    r"C:\Program Files\RedHat\java*",
    r"C:\Program Files\SapMachine\*",
    r"C:\Program Files\JetBrains\*\jbr",
    r"C:\Program Files\Android\Android Studio\jbr",
)


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "java_trust_backup.json")


# ── discovery ─────────────────────────────────────────────────────────────────

def _java_homes() -> list:
    """Candidate Java homes: JAVA_HOME, whatever is on PATH, and the standard
    install roots of the common JDK vendors."""
    homes = []

    def add(p):
        if p:
            p = os.path.normpath(p)
            if p not in homes and os.path.isdir(p):
                homes.append(p)

    add(os.environ.get("JAVA_HOME", ""))
    # java.exe on PATH -> its home is two levels up (<home>\bin\java.exe).
    try:
        r = subprocess.run(["where", "java"], capture_output=True, text=True,
                           creationflags=_NO_WINDOW, timeout=15)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.lower().endswith("java.exe"):
                add(os.path.dirname(os.path.dirname(line)))
    except Exception:
        pass
    for pattern in _SEARCH_GLOBS:
        try:
            for p in glob.glob(pattern):
                add(p)
        except Exception:
            pass
    return homes


def find_keystores() -> list:
    """[(keystore_path, keytool_path)] for every Java install we can write to.

    Java 8 keeps the store at jre/lib/security/cacerts; 9+ at lib/security/cacerts.
    A JDK that bundles a JRE has both, and both are checked because a build may
    invoke either."""
    found = []
    seen = set()
    for home in _java_homes():
        keytool = os.path.join(home, "bin", "keytool.exe")
        if not os.path.isfile(keytool):
            continue
        for rel in (("lib", "security", "cacerts"),
                    ("jre", "lib", "security", "cacerts")):
            ks = os.path.join(home, *rel)
            key = ks.lower()
            if os.path.isfile(ks) and key not in seen:
                seen.add(key)
                found.append((ks, keytool))
    return found


# ── keytool plumbing ──────────────────────────────────────────────────────────

def _run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           creationflags=_NO_WINDOW, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def _list_aliases(keystore: str, keytool: str, storepass: str) -> list:
    rc, out = _run([keytool, "-list", "-keystore", keystore,
                    "-storepass", storepass])
    if rc != 0:
        return []
    return [m.group(1).strip().lower()
            for m in re.finditer(r"^([^,\r\n]+),", out, re.M)]


def _storepass_for(keystore: str, keytool: str) -> str:
    """The default JDK password, or '' if it does not open the store (a managed
    image sometimes changes it — we skip those rather than guess)."""
    rc, _ = _run([keytool, "-list", "-keystore", keystore,
                  "-storepass", _DEFAULT_STOREPASS], timeout=60)
    return _DEFAULT_STOREPASS if rc == 0 else ""


def _split_pem(pem_path: str) -> list:
    """The individual PEM certificate blocks in a file. keytool -importcert reads
    only the FIRST certificate in a multi-cert file, so a chain must be imported
    one alias at a time."""
    try:
        with open(pem_path, "rb") as f:
            raw = f.read()
    except OSError:
        return []
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", raw, re.S)
    return [b.decode("ascii", "ignore") for b in blocks]


def _alias_for(block: str, index: int) -> str:
    """Stable, collision-proof alias: prefix + a hash of the certificate itself,
    so re-running is idempotent and two different CAs never share an alias."""
    body = re.sub(r"\s+", "", block.split("-----")[2])
    try:
        der = base64.b64decode(body, validate=True)
        tag = hashlib.sha256(der).hexdigest()[:12]
    except Exception:
        tag = f"{index:02d}"
    return f"{_ALIAS_PREFIX}-{tag}"


# ── backup ────────────────────────────────────────────────────────────────────

def _read_backup():
    try:
        with open(_backup_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_backup(data):
    try:
        os.makedirs(_data_dir(), exist_ok=True)
        with open(_backup_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _clear_backup():
    try:
        os.remove(_backup_path())
    except OSError:
        pass


# ── public API ────────────────────────────────────────────────────────────────

def apply(corporate_pem: str) -> dict:
    """Import every certificate in `corporate_pem` into every Java truststore we
    can open. Records each (keystore, alias) actually created so restore() can
    remove exactly those.

    Returns {"stores": int, "imported": int, "skipped": [str], "details": [str]}.
    Never raises: a JDK we cannot touch is reported, not fatal."""
    result = {"stores": 0, "imported": 0, "skipped": [], "details": []}
    blocks = _split_pem(corporate_pem)
    if not blocks:
        return result

    stores = find_keystores()
    result["stores"] = len(stores)
    if not stores:
        return result

    # Preserve a pre-existing run's record: if we crashed after importing, that
    # older list is the truth about what must be removed.
    created = _read_backup() or []
    created_keys = {(c["keystore"].lower(), c["alias"]) for c in created}

    tmp_dir = os.path.join(_data_dir(), "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    for keystore, keytool in stores:
        storepass = _storepass_for(keystore, keytool)
        if not storepass:
            result["skipped"].append(
                f"{keystore} (keystore password is not the JDK default)")
            continue
        existing = set(_list_aliases(keystore, keytool, storepass))
        for i, block in enumerate(blocks):
            alias = _alias_for(block, i)
            if alias in existing:
                # Already imported (a previous run, or the same CA twice).
                if (keystore.lower(), alias) not in created_keys:
                    continue    # not ours -> leave it, and do not claim it
                result["details"].append(f"{alias} already in {keystore}")
                continue
            tmp = os.path.join(tmp_dir, f"{alias}.pem")
            try:
                with open(tmp, "w", encoding="ascii") as f:
                    f.write(block if block.endswith("\n") else block + "\n")
                rc, out = _run([keytool, "-importcert", "-noprompt",
                                "-trustcacerts", "-alias", alias,
                                "-file", tmp, "-keystore", keystore,
                                "-storepass", storepass])
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            if rc == 0:
                created.append({"keystore": keystore, "alias": alias})
                created_keys.add((keystore.lower(), alias))
                result["imported"] += 1
            else:
                result["skipped"].append(
                    f"{keystore} ({out.strip().splitlines()[-1] if out.strip() else 'keytool failed'})")

    if created:
        _write_backup(created)
    return result


def restore() -> bool:
    """Delete exactly the aliases apply() created, from exactly the keystores it
    created them in. Idempotent: no backup -> no-op. Returns True if anything was
    removed."""
    created = _read_backup()
    if not created:
        return False
    removed = 0
    for entry in created:
        keystore = entry.get("keystore", "")
        alias = entry.get("alias", "")
        if not keystore or not alias or not alias.startswith(_ALIAS_PREFIX):
            continue    # never delete something we did not create
        keytool = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(keystore))),
            "bin", "keytool.exe")
        if not os.path.isfile(keytool):
            # Java 8 layout: <home>\jre\lib\security\cacerts -> one level further up.
            keytool = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.dirname(keystore)))), "bin", "keytool.exe")
        if not os.path.isfile(keytool) or not os.path.isfile(keystore):
            continue    # JDK uninstalled since we imported — nothing to undo
        rc, _ = _run([keytool, "-delete", "-alias", alias,
                      "-keystore", keystore, "-storepass", _DEFAULT_STOREPASS])
        if rc == 0:
            removed += 1
    _clear_backup()
    return removed > 0


def current_state() -> str:
    """One-line diagnostic: how many Java truststores are present and how many
    ProxyForce aliases are currently recorded."""
    stores = find_keystores()
    created = _read_backup() or []
    if not stores:
        return "no Java installation found"
    return (f"{len(stores)} Java truststore(s) found; "
            f"{len(created)} ProxyForce alias(es) currently imported")
