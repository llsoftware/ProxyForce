#!/usr/bin/env python3
"""Generate an Ed25519 release-signing keypair for ProxyForce's auto-updater.

Run ONCE, locally (the private key must never touch CI logs or the repo):

    python tools/gen_keypair.py

Then:
  * Add the printed PRIVATE seed as the GitHub Actions secret PROXYFORCE_SIGNING_KEY
    (Settings → Secrets and variables → Actions → New repository secret).
  * Paste the printed PUBLIC key into core/updater.py → RELEASE_PUBKEY_B64.

Rotating the key invalidates auto-update for clients running an older embedded key;
ship the new public key in a normal (manually-installed) release first.
"""

import os
import sys
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import _ed25519  # noqa: E402


def main():
    seed = os.urandom(32)
    pub = _ed25519.publickey(seed)
    print("=" * 70)
    print("PRIVATE seed  →  GitHub Actions secret  PROXYFORCE_SIGNING_KEY")
    print("    " + base64.b64encode(seed).decode())
    print()
    print("PUBLIC key    →  core/updater.py  RELEASE_PUBKEY_B64")
    print("    " + base64.b64encode(pub).decode())
    print("=" * 70)
    print("Keep the private seed secret. Never commit it.")


if __name__ == "__main__":
    main()
