# Sealed mail format (v1)

npubmail stores every message encrypted to the mailbox owner's Nostr key. The
server keeps only ciphertext. This document is enough to write a decryptor in
any language; `{{BASE}}/api/seal-vectors.json` has test vectors and
`{{BASE}}/api/open_sealed.py` is a dependency-light reference implementation
(pure-Python secp256k1 plus pycryptodome) written from this text alone.

## Where it appears

`GET /v1/messages` returns each message with `sealed` (the header part).
`GET /v1/messages/{id}` additionally returns `sealed_body` (the body part).
When a part is sealed, the corresponding plaintext fields in the response
are empty. `id`, `received_at` and `size` stay in the clear.

## String format

```
v1:<E>:<B>
```

- `v1` – format version. Split on `:` at most twice (base64 never contains `:`).
- `E` – 64 lowercase hex characters: the x-only (BIP-340) public key of a fresh
  ephemeral secp256k1 key, one per sealed part.
- `B` – standard base64 **with padding** (RFC 4648 §4, not URL-safe) of
  `nonce (24 bytes) || ciphertext || tag (16 bytes)`.

## Decryption

Inputs: your secret key `sk` (32 bytes; decode `nsec1…` with bech32 first) and
the sealed string.

1. **Point.** Lift `E` to a curve point with **even y** (BIP-340 `lift_x`).
2. **ECDH.** `shared_x` = the 32-byte big-endian x coordinate of `sk · E`.
   Unhashed: do *not* use libsecp256k1's default ECDH, which SHA-256s the
   point; take the raw x.
3. **Conversation key** (identical to the NIP-44 v2 conversation key):
   `ck = HKDF-Extract(salt = "nip44-v2", IKM = shared_x)`
   which is `HMAC-SHA256(key = "nip44-v2", msg = shared_x)` (32 bytes).
   Only the extract step: no HKDF-Expand, no NIP-44 message keys, no padding.
4. **AEAD.** XChaCha20-Poly1305 (the IETF ChaCha20-Poly1305 construction with
   a 24-byte nonce via HChaCha20; libsodium
   `crypto_aead_xchacha20poly1305_ietf_decrypt`):
   - key = `ck`
   - nonce = first 24 bytes of `B`
   - ciphertext‖tag = the remaining bytes
   - **additional data = the 15 ASCII bytes `keymail-seal-v1`** (a historical
     name; it is part of format v1 and will not change).
5. The plaintext is UTF-8 JSON.

Sealing is the mirror image: generate an ephemeral key `e`, compute `shared_x`
of `e · P_owner` (owner pubkey lifted with even y), derive `ck`, pick a random
24-byte nonce, output `v1:<x(e·G)>:<base64(nonce‖AEAD(ck, nonce, pt, AD))>`.

Common mistakes behind "my decryptor fails":

- hashing the ECDH output (libsecp256k1 / some wallets do this by default);
- running full NIP-44 (HKDF-Expand, ChaCha20 + HMAC, padding) instead of
  using the conversation key directly with XChaCha20-Poly1305;
- forgetting the additional data `keymail-seal-v1`, or using `npubmail-…`;
- treating the nonce as 12 bytes (that is plain ChaCha20-Poly1305);
- URL-safe base64 or stripping padding.

## Plaintext JSON

`sealed` (header):

```json
{"to": "...", "mail_from": "...", "from": "...", "subject": "...",
 "date": "...", "auth": {"spf": "pass", "dkim": ["example.com"], "aligned": true},
 "codes": ["482913"], "warnings": []}
```

`date` may be absent. `sealed_body` (body):

```json
{"text": "...", "html": "...", "links": [{"url": "...", "action": true}]}
```

Each of `text`, `html`, `links` may be absent. Unknown fields may be added
later; ignore them.

## Test vectors

`{{BASE}}/api/seal-vectors.json` (source: `internal/seal/testdata/vectors.json`).
Each entry gives `owner_secret`, `owner_pubkey`, `ephemeral_secret`,
`ephemeral_pubkey`, `shared_x`, `conversation_key`, `nonce`, `plaintext` and
`sealed`. A correct implementation reproduces `shared_x` and
`conversation_key`, and opens `sealed` to `plaintext`. A sealer given the same
ephemeral secret and nonce reproduces `sealed` byte for byte. The Go test
`TestVectors` fails if the server's format ever drifts from these vectors.

```
python3 open_sealed.py --vectors seal-vectors.json
python3 open_sealed.py --key ~/.config/npubmail/nsec 'v1:…'
```
