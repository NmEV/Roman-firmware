#!/usr/bin/env python3
"""Verify a Roman signature - the acceptance check for POST /sign.

Two modes:

  # ask the board for a signature and verify it (also reports the stack headroom)
  python verify_signature.py --host 192.168.7.1

  # verify a signature you already have
  python verify_signature.py --offline --pk <base64> --signature <base64> \
      --message "c:x:1:dev-01"

The signed message is challenge:context:timestamp:device_id, exactly what
http_server.c builds.

Ed25519 is implemented here (RFC 8032) rather than pulled from a library: the
point is to be independent of the firmware, and the implementation is checked
against the RFC 8032 test vectors on every run *before* it judges anything, so a
broken verifier fails loudly instead of accusing the board. It needs nothing but
the standard library - no openssl, no cryptography, no pynacl.
"""

import argparse
import base64
import hashlib
import json
import sys
import urllib.request

# --- Ed25519 (RFC 8032) ------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    return P - x if x % 2 else x


_BY = (4 * pow(5, P - 2, P)) % P
_B = (_recover_x(_BY), _BY, 1, (_recover_x(_BY) * _BY) % P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(point, scalar):
    if scalar == 0:
        return (0, 1, 1, 0)
    half = _mul(point, scalar >> 1)
    doubled = _add(half, half)
    return _add(doubled, point) if scalar & 1 else doubled


def _decode_point(enc):
    if len(enc) != 32:
        raise ValueError("public key must be 32 bytes")
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    x = _recover_x(y)
    if (x & 1) != (enc[31] >> 7):
        x = P - x
    return (x, y, 1, x * y % P)


def _encode_point(point):
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return ((y & ((1 << 255) - 1)) | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(pk, message, signature):
    """True when signature is a valid Ed25519 signature of message under pk."""
    if len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + pk + message).digest(), "little") % L
    left = _encode_point(_mul(_B, s))
    right = _encode_point(_add(_decode_point(signature[:32]), _mul(_decode_point(pk), h)))
    return left == right


RFC8032_VECTORS = (
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
)


def self_check():
    """Refuse to judge the board with an unproven verifier."""
    for index, (pk_hex, msg_hex, sig_hex) in enumerate(RFC8032_VECTORS, 1):
        pk, msg, sig = bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
        if not ed25519_verify(pk, msg, sig):
            raise SystemExit("RFC 8032 test vector %d does not verify - verifier is broken" % index)
        if ed25519_verify(pk, msg + b"x", sig):
            raise SystemExit("verifier accepts a modified message - refusing to judge the board")
    print("verifier    : RFC 8032 test vectors pass")


# --- board access ------------------------------------------------------------

def http(host, method, path, body=None, timeout=15.0):
    data = body.encode() if body is not None else None
    request = urllib.request.Request("http://%s%s" % (host, path), data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode())


def check_board(host, challenge, context, timestamp):
    # /debug is a POST route (like the bench tool uses); GET /debug is a 404 by
    # design, only /health, /info and /sign answer GET.
    status, snapshot = http(host, "POST", "/debug", "{}")
    debug = snapshot.get("debug", {})
    device_id = debug.get("roman", {}).get("device_id")
    pk_b64 = debug.get("roman", {}).get("ed25519_pk")
    if not device_id or not pk_b64:
        raise SystemExit("board is not provisioned (see POST /write)")

    status, reply = http(host, "POST", "/sign", json.dumps(
        {"challenge": challenge, "context": context, "timestamp": timestamp}))
    if status != 200 or "signature" not in reply:
        raise SystemExit("POST /sign answered %s: %s" % (status, reply))

    message = ("%s:%s:%s:%s" % (challenge, context, timestamp, device_id)).encode()
    signature = base64.b64decode(reply["signature"])
    pk = base64.b64decode(pk_b64)
    print("host        : %s (firmware %s, device_id %s)" % (host, debug.get("firmware"), device_id))
    print("message     : %r" % message)
    print("signature   : %s" % reply["signature"])
    ok = ed25519_verify(pk, message, signature)
    print("signature   : %s" % ("VALID" if ok else "INVALID"))
    if ok:
        print("tamper check: %s" % ("rejected" if not ed25519_verify(pk, message + b"!", signature) else "ACCEPTED (bug!)"))

    status, after = http(host, "POST", "/debug", "{}")
    stack = after.get("debug", {}).get("stack", {})
    web = after.get("debug", {}).get("web", {})
    print("stack       : used_max %s / total %s, free_min %s" % (
        stack.get("used_max"), stack.get("total"), stack.get("free_min")))
    print("counters    : sign_ok %s, sign_bad %s, reset_by_watchdog %s, last_stage %s" % (
        web.get("sign_ok"), web.get("sign_bad"),
        after.get("debug", {}).get("reset_by_watchdog"),
        after.get("debug", {}).get("roman", {}).get("last_stage")))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description="Verify a Roman Ed25519 signature.")
    parser.add_argument("--host", default="192.168.7.1", help="board address (default 192.168.7.1)")
    parser.add_argument("--challenge", default="probe")
    parser.add_argument("--context", default="debug-tool")
    parser.add_argument("--timestamp", default="0")
    parser.add_argument("--offline", action="store_true", help="verify a signature from the command line instead")
    parser.add_argument("--pk", help="base64 Ed25519 public key (offline)")
    parser.add_argument("--signature", help="base64 signature (offline)")
    parser.add_argument("--message", help="the signed message (offline)")
    args = parser.parse_args()

    self_check()

    if args.offline:
        if not (args.pk and args.signature and args.message):
            parser.error("--offline needs --pk, --signature and --message")
        pk = base64.b64decode(args.pk)
        ok = ed25519_verify(pk, args.message.encode(), base64.b64decode(args.signature))
        print("message     : %r" % args.message.encode())
        print("signature   : %s" % ("VALID" if ok else "INVALID"))
        return 0 if ok else 1

    return check_board(args.host, args.challenge, args.context, args.timestamp)


if __name__ == "__main__":
    sys.exit(main())
