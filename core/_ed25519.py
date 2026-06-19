"""
Pure-Python Ed25519 (RFC 8032) — keygen / sign / verify, no third-party deps.

Adapted from Daniel J. Bernstein's public-domain reference implementation
(https://ed25519.cr.yp.to/python/ed25519.py), with the modular exponentiation
delegated to the built-in `pow(b, e, m)` and `scalarmult` made iterative so there
is no recursion-depth risk and verification of a small message (a SHA256SUMS file)
completes in well under a second.

ProxyForce uses this to verify the signature over a release's SHA256SUMS file with
a public key embedded in the app — defending the auto-updater against a tampered or
hijacked GitHub release without pulling in a binary crypto dependency (which would
also break the offline-wheel build).

Public API:
    publickey(seed: bytes32) -> bytes32
    sign(seed: bytes32, message: bytes) -> bytes64
    verify(public_key: bytes32, message: bytes, signature: bytes64) -> bool
"""

import hashlib

_b = 256
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]


def _scalarmult(P, e: int):
    Q = [0, 1]               # neutral element
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    return ((y & ((1 << (_b - 1)) - 1)) | ((x & 1) << (_b - 1))).to_bytes(_b // 8, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _Hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def _secret_scalar(seed: bytes) -> int:
    h = _H(seed)
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def publickey(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    A = _scalarmult(_B, _secret_scalar(seed))
    return _encodepoint(A)


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature of `message` under `seed`."""
    h = _H(seed)
    a = _secret_scalar(seed)
    pk = _encodepoint(_scalarmult(_B, a))
    r = _Hint(h[_b // 8:_b // 4] + message) % _l
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + message) * a) % _l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point is not on curve")
    return P


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` under
    `public_key`. Never raises — any malformed input returns False."""
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
        S = _decodeint(signature[32:])
        h = _Hint(signature[:32] + public_key + message) % _l
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False
