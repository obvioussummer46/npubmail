// SPDX-License-Identifier: MIT

// Package seal encrypts stored mail to the mailbox owner's Nostr key, so the
// server keeps only ciphertext it cannot read.
//
// Format: "v1:<ephemeral x-only pubkey hex>:<base64(nonce24 || ciphertext)>".
// Key agreement is secp256k1 ECDH between a fresh ephemeral key and the
// owner's pubkey, HKDF-extracted exactly as NIP-44's conversation key; the
// payload is XChaCha20-Poly1305, so there is no size limit (NIP-44 itself
// caps plaintext at 64 KiB, too small for mail).
package seal

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"golang.org/x/crypto/chacha20poly1305"
)

const prefix = "v1:"

var ad = []byte("keymail-seal-v1")

// Seal encrypts plaintext so only the holder of ownerPub's secret key can read it.
// The full construction is specified in docs/SEAL.md, with test vectors in
// testdata/vectors.json.
func Seal(ownerPub string, plaintext []byte) (string, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return sealWith(nostr.GeneratePrivateKey(), nonce, ownerPub, plaintext)
}

// sealWith is Seal with a fixed ephemeral key and nonce (test vectors only).
func sealWith(eph string, nonce []byte, ownerPub string, plaintext []byte) (string, error) {
	ephPub, err := nostr.GetPublicKey(eph)
	if err != nil {
		return "", err
	}
	ck, err := nip44.GenerateConversationKey(ownerPub, eph)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return "", err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return "", errors.New("seal: nonce must be 24 bytes")
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, ad)
	return prefix + ephPub + ":" + base64.StdEncoding.EncodeToString(out), nil
}

var ErrFormat = errors.New("seal: malformed ciphertext")

// Open decrypts with the owner's secret key (hex).
func Open(ownerSecret, sealed string) ([]byte, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return nil, ErrFormat
	}
	parts := strings.SplitN(sealed[len(prefix):], ":", 2)
	if len(parts) != 2 || len(parts[0]) != 64 {
		return nil, ErrFormat
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(raw) < chacha20poly1305.NonceSizeX {
		return nil, ErrFormat
	}
	ck, err := nip44.GenerateConversationKey(parts[0], ownerSecret)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, raw[:chacha20poly1305.NonceSizeX], raw[chacha20poly1305.NonceSizeX:], ad)
}
