// SPDX-License-Identifier: MIT
// Reference decryptor for npubmail sealed mail (JavaScript, Node 18+ or browser).
//
//   npm i @noble/curves @noble/ciphers @noble/hashes @scure/base
//   node open_sealed.mjs --vectors seal-vectors.json
//   node open_sealed.mjs --key ~/.config/npubmail/nsec 'v1:<eph>:<b64>'
//
// Spec: https://npubmail.com/api/seal. Test/reference only: the curve code is not constant-time.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";
import { readFileSync } from "node:fs";

const AD = new TextEncoder().encode("keymail-seal-v1"); // fixed for format v1
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

export function secretFromNsec(s) {
  s = s.trim();
  if (!s.startsWith("nsec1")) return unhex(s);
  return Uint8Array.from(bech32.fromWords(bech32.decode(s, 1000).words));
}

export function conversationKey(secret, ephPubHex) {
  // 1+2: lift x-only pubkey with even y ("02" prefix), raw ECDH x (NOT hashed)
  const point = secp256k1.getSharedSecret(secret, unhex("02" + ephPubHex), true);
  const sharedX = point.slice(1, 33);
  // 3: HKDF-Extract(salt="nip44-v2", IKM=sharedX) == HMAC-SHA256(key=salt, msg=IKM)
  return hmac(sha256, new TextEncoder().encode("nip44-v2"), sharedX);
}

export function openSealed(secret, sealed) {
  const [ver, eph, b64] = [sealed.slice(0, 2), ...sealed.slice(3).split(":")];
  if (ver !== "v1" || eph.length !== 64) throw new Error("not a v1 sealed string");
  const raw = Uint8Array.from(Buffer.from(b64, "base64"));
  const nonce = raw.slice(0, 24); // 24 bytes: XChaCha, not ChaCha
  const ctAndTag = raw.slice(24); // noble expects ciphertext||tag together
  const pt = xchacha20poly1305(conversationKey(secret, eph), nonce, AD).decrypt(ctAndTag);
  return new TextDecoder().decode(pt);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  if (a[0] === "--vectors") {
    JSON.parse(readFileSync(a[1], "utf8")).forEach((v, i) => {
      const sk = unhex(v.owner_secret);
      if (hex(conversationKey(sk, v.ephemeral_pubkey)) !== v.conversation_key) throw new Error(`vector ${i}: conversation key`);
      if (openSealed(sk, v.sealed) !== v.plaintext) throw new Error(`vector ${i}: plaintext`);
      console.log(`vector ${i} ok: ${v.comment}`);
    });
  } else if (a[0] === "--key") {
    console.log(openSealed(secretFromNsec(readFileSync(a[1], "utf8")), a[2]));
  } else {
    console.error("usage: --vectors file | --key nsecfile 'v1:...'");
    process.exit(2);
  }
}
