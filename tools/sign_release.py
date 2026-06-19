#!/usr/bin/env python3
"""Sign a release's SHA256SUMS file with the Ed25519 private seed (CI step).

    python tools/sign_release.py <SHA256SUMS path> <output .sig path>

The base64 private seed is read from the env var PROXYFORCE_SIGNING_KEY (a GitHub
Actions secret). If it is not set, this prints a warning and exits 0 WITHOUT writing
a signature — so tagging still builds, but the release will lack a .sig and the
auto-updater will (correctly) refuse to install it until signing is configured.
"""

import os
import sys
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import _ed25519  # noqa: E402


def main():
    if len(sys.argv) != 3:
        print("usage: sign_release.py <SHA256SUMS> <out.sig>")
        sys.exit(2)
    sums_path, sig_path = sys.argv[1], sys.argv[2]

    seed_b64 = os.environ.get("PROXYFORCE_SIGNING_KEY", "").strip()
    if not seed_b64:
        print("WARNING: PROXYFORCE_SIGNING_KEY not set — release will be UNSIGNED "
              "(auto-update will refuse it). Set the secret to enable signing.")
        sys.exit(0)

    try:
        seed = base64.b64decode(seed_b64)
    except Exception as e:
        print(f"ERROR: PROXYFORCE_SIGNING_KEY is not valid base64: {e}")
        sys.exit(4)
    if len(seed) != 32:
        print(f"ERROR: signing seed must decode to 32 bytes (got {len(seed)}).")
        sys.exit(4)

    with open(sums_path, "rb") as f:
        msg = f.read()
    sig = _ed25519.sign(seed, msg)
    with open(sig_path, "wb") as f:
        f.write(sig)
    print(f"Signed {sums_path} -> {sig_path} ({len(sig)} bytes)")


if __name__ == "__main__":
    main()
