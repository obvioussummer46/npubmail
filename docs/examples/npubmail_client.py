#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete npubmail client in one file, written from the public docs only.

Shows every step of "route 2" (talk to the HTTP API without the npubmail
binaries): Nostr key, NIP-98 signed requests, NIP-13 proof of work for mailbox
creation, listing and decrypting mail, sending, and the 402 payment flow.

    pip install pycryptodome          # only for XChaCha20-Poly1305
    python3 npubmail_client.py keygen > nsec && chmod 600 nsec
    python3 npubmail_client.py --key nsec init myagent
    python3 npubmail_client.py --key nsec whoami
    python3 npubmail_client.py --key nsec ls
    python3 npubmail_client.py --key nsec read <id>
    python3 npubmail_client.py --key nsec send to@example.com "Subject" "Body" [payment_id]

Everything else is the Python standard library. The secp256k1 code is plain
and readable, not constant-time: fine for an agent on its own machine, not a
shared host. Spec: https://npubmail.com/api and https://npubmail.com/api/seal
"""
import base64, hashlib, hmac, json, os, secrets, sys, time, urllib.error, urllib.request

try:
    from Crypto.Cipher import ChaCha20_Poly1305
except ImportError:
    from Cryptodome.Cipher import ChaCha20_Poly1305

BASE = os.environ.get("NPUBMAIL_URL", "https://npubmail.com").rstrip("/")

# ---- secp256k1 / BIP-340 (stdlib only) ---------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    l = (3 * a[0] * a[0] * pow(2 * a[1], -1, P)) if a == b else ((b[1] - a[1]) * pow(b[0] - a[0], -1, P))
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt, k = _add(pt, pt), k >> 1
    return r


def _lift_x(x):
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - pow(x, 3, P) - 7) % P: raise ValueError("not on curve")
    return (x, y if y % 2 == 0 else P - y)


def _tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def pubkey_hex(sk: bytes) -> str:
    return _mul(int.from_bytes(sk, "big"), G)[0].to_bytes(32, "big").hex()


def schnorr_sign(sk: bytes, msg32: bytes) -> str:
    d = int.from_bytes(sk, "big")
    Pt = _mul(d, G)
    if Pt[1] % 2: d = N - d
    px = Pt[0].to_bytes(32, "big")
    aux = secrets.token_bytes(32)
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k = int.from_bytes(_tagged("BIP0340/nonce", t + px + msg32), "big") % N
    R = _mul(k, G)
    if R[1] % 2: k = N - k
    rx = R[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + msg32), "big") % N
    return (rx + ((k + e * d) % N).to_bytes(32, "big")).hex()


# ---- keys (bech32 nsec) ------------------------------------------------
_B = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(v):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    c = 1
    for x in v:
        b = c >> 25
        c = (c & 0x1ffffff) << 5 ^ x
        for i in range(5): c ^= g[i] if (b >> i) & 1 else 0
    return c


def _conv(data, f, t, pad):
    acc = bits = 0; out = []
    for v in data:
        acc = (acc << f) | v; bits += f
        while bits >= t: bits -= t; out.append((acc >> bits) & ((1 << t) - 1))
    if pad and bits: out.append((acc << (t - bits)) & ((1 << t) - 1))
    return out


def nsec_encode(sk: bytes) -> str:
    d = _conv(sk, 8, 5, True); hrp = "nsec"
    exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(exp + d + [0] * 6) ^ 1
    return hrp + "1" + "".join(_B[x] for x in d + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def load_secret(text: str) -> bytes:
    s = text.strip()
    if s.startswith("nsec1"):
        return bytes(_conv([_B.index(c) for c in s[5:-6]], 5, 8, False))
    return bytes.fromhex(s)


# ---- NIP-98 auth (+ NIP-13 PoW) ---------------------------------------
def _event_id(ev):
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).digest()


def _zero_bits(h: bytes) -> int:
    n = 0
    for b in h:
        if b == 0: n += 8; continue
        return n + 8 - b.bit_length()
    return n


def auth_header(sk, method, url, body=b"", pow_bits=0):
    ev = {"pubkey": pubkey_hex(sk), "created_at": int(time.time()), "kind": 27235, "content": "",
          "tags": [["u", url], ["method", method.upper()], ["n", secrets.token_hex(8)]]}
    if body:
        ev["tags"].append(["payload", hashlib.sha256(body).hexdigest()])
    if pow_bits:
        ev["tags"].append(["nonce", "0", str(pow_bits)])
        n = 0
        while True:
            ev["tags"][-1][1] = str(n)
            h = _event_id(ev)
            if _zero_bits(h) >= pow_bits: break
            n += 1
    h = _event_id(ev)
    ev["id"] = h.hex()
    ev["sig"] = schnorr_sign(sk, h)
    return "Nostr " + base64.b64encode(json.dumps(ev, separators=(",", ":")).encode()).decode()


def call(sk, method, path, payload=None, pow_bits=0):
    url = BASE + path  # sign the exact URL incl. query string
    body = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(url, data=body or None, method=method)
    req.add_header("Authorization", auth_header(sk, method, url, body, pow_bits))
    if body: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=150) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except ValueError: return e.code, {"error": raw.decode(errors="replace")}


# ---- sealed mail (spec: /api/seal) --------------------------------------
def open_sealed(sk: bytes, sealed: str) -> dict:
    ver, eph, b64 = sealed.split(":", 2)
    assert ver == "v1" and len(eph) == 64
    shared_x = _mul(int.from_bytes(sk, "big"), _lift_x(int(eph, 16)))[0].to_bytes(32, "big")
    ck = hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()
    raw = base64.b64decode(b64)
    c = ChaCha20_Poly1305.new(key=ck, nonce=raw[:24])
    c.update(b"keymail-seal-v1")
    return json.loads(c.decrypt_and_verify(raw[24:-16], raw[-16:]))


def unseal(sk, m):
    for f in ("sealed", "sealed_body"):
        if m.get(f): m.update(open_sealed(sk, m.pop(f)))
    return m


# ---- CLI ----------------------------------------------------------------
def main():
    a = sys.argv[1:]
    if a and a[0] == "keygen":
        print(nsec_encode(secrets.randbelow(N - 1).__add__(1).to_bytes(32, "big"))); return
    if len(a) < 3 or a[0] != "--key":
        print(__doc__); sys.exit(2)
    sk = load_secret(open(a[1]).read()); cmd, rest = a[2], a[3:]
    if cmd == "init":
        name = rest[0] if rest else ""
        _, d = call(sk, "GET", "/.well-known/npubmail")
        st, out = call(sk, "POST", "/v1/mailbox", {"name": name}, pow_bits=int(d.get("create_pow", 20)))
    elif cmd == "whoami":
        st, out = call(sk, "GET", "/v1/mailbox")
    elif cmd == "ls":
        st, out = call(sk, "GET", "/v1/messages?limit=20")
        if st == 200:
            out = [{k: unseal(sk, m).get(k) for k in ("id", "received_at", "from", "subject", "codes")}
                   for m in out.get("messages", [])]
    elif cmd == "read":
        st, out = call(sk, "GET", "/v1/messages/" + rest[0])
        if st == 200: out = unseal(sk, out)
    elif cmd == "send":
        req = {"to": [rest[0]], "subject": rest[1], "text": rest[2]}
        if len(rest) > 3: req["payment_id"] = rest[3]
        st, out = call(sk, "POST", "/v1/send", req)
        if st == 402:
            print(f"PAYMENT REQUIRED: {out.get('price_sats')} sats. Pay this Lightning invoice, then repeat "
                  f"the same send with payment_id={out.get('payment_id')}:\n{out.get('bolt11')}", file=sys.stderr)
    else:
        print(__doc__); sys.exit(2)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    sys.exit(0 if st < 300 else 1)


if __name__ == "__main__":
    main()
