#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reference decryptor for npubmail sealed mail, written from docs/SEAL.md only.

    pip install pycryptodome
    python3 open_sealed.py --vectors internal/seal/testdata/vectors.json
    python3 open_sealed.py --key ~/.config/npubmail/nsec 'v1:<eph>:<b64>'

No npubmail code is used: ECDH is plain secp256k1 math below, HKDF-extract is
HMAC-SHA256, and the AEAD is XChaCha20-Poly1305 from pycryptodome.

Reference and testing only: the curve arithmetic is plain Python and not
constant-time. Fine on your own machine; on shared hosts use a vetted library.
"""
import argparse, base64, hashlib, hmac, json, sys

try:
    from Crypto.Cipher import ChaCha20_Poly1305  # pip install pycryptodome
except ImportError:
    from Cryptodome.Cipher import ChaCha20_Poly1305  # pycryptodomex

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
AD = b"keymail-seal-v1"  # historical name; fixed forever for format v1


def lift_x(x):  # BIP-340: the point with this x and even y
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - (x ** 3 + 7)) % P:
        raise ValueError("pubkey not on curve")
    return (x, y if y % 2 == 0 else P - y)


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt, k = add(pt, pt), k >> 1
    return r


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P)
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P)
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def nsec_to_hex(s):
    s = s.strip()
    if not s.startswith("nsec1"):
        return s
    data = [BECH.index(c) for c in s[5:]][:-6]
    acc, bits, out = 0, 0, bytearray()
    for v in data:
        acc, bits = (acc << 5) | v, bits + 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return out.hex()


def conversation_key(secret_hex, eph_pub_hex):
    shared_x = mul(int(secret_hex, 16), lift_x(int(eph_pub_hex, 16)))[0]
    # NIP-44 v2: HKDF-Extract(salt="nip44-v2", IKM=shared_x)
    return hmac.new(b"nip44-v2", shared_x.to_bytes(32, "big"), hashlib.sha256).digest()


def open_sealed(secret_hex, sealed):
    ver, eph, b64 = sealed.split(":", 2)
    if ver != "v1" or len(eph) != 64:
        raise ValueError("not a v1 sealed string")
    raw = base64.b64decode(b64)
    nonce, ct, tag = raw[:24], raw[24:-16], raw[-16:]
    c = ChaCha20_Poly1305.new(key=conversation_key(secret_hex, eph), nonce=nonce)  # 24-byte nonce = XChaCha
    c.update(AD)
    return c.decrypt_and_verify(ct, tag)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--key")
    ap.add_argument("sealed", nargs="?")
    a = ap.parse_args()
    if a.vectors:
        vs = json.load(open(a.vectors))
        for i, v in enumerate(vs):
            ck = conversation_key(v["owner_secret"], v["ephemeral_pubkey"]).hex()
            assert ck == v["conversation_key"], f"vector {i}: conversation key mismatch"
            pt = open_sealed(v["owner_secret"], v["sealed"]).decode()
            assert pt == v["plaintext"], f"vector {i}: plaintext mismatch"
            print(f"vector {i} ok: {v['comment']}")
        return
    sk = nsec_to_hex(open(a.key).read() if a.key else sys.stdin.readline())
    print(open_sealed(sk, a.sealed).decode())


if __name__ == "__main__":
    main()
