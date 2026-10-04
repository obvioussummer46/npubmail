// SPDX-License-Identifier: MIT

// Package cashu is a small Cashu ecash wallet (NUT-00/01/02/03/04/05/07/08/09/
// 13/20) used by the npubmail client as an optional convenience wallet. It
// keeps proofs in a local JSON file and derives all secrets deterministically
// from a seed, so a lost file can be restored from the seed (NUT-09/13).
package cashu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var domainSep = []byte("Secp256k1_HashToCurve_Cashu_")

// HashToCurve maps a message to a curve point (NUT-00).
func HashToCurve(msg []byte) (*btcec.PublicKey, error) {
	h := sha256.Sum256(append(append([]byte{}, domainSep...), msg...))
	var ctr [4]byte
	for i := uint32(0); i < 1<<16; i++ {
		binary.LittleEndian.PutUint32(ctr[:], i)
		c := sha256.Sum256(append(h[:], ctr[:]...))
		if pk, err := btcec.ParsePubKey(append([]byte{0x02}, c[:]...)); err == nil {
			return pk, nil
		}
	}
	return nil, errors.New("cashu: no point found")
}

func add(a, b *btcec.PublicKey) *btcec.PublicKey {
	var ja, jb, r btcec.JacobianPoint
	a.AsJacobian(&ja)
	b.AsJacobian(&jb)
	btcec.AddNonConst(&ja, &jb, &r)
	r.ToAffine()
	return btcec.NewPublicKey(&r.X, &r.Y)
}

func mul(k *btcec.ModNScalar, p *btcec.PublicKey) *btcec.PublicKey {
	var jp, r btcec.JacobianPoint
	p.AsJacobian(&jp)
	btcec.ScalarMultNonConst(k, &jp, &r)
	r.ToAffine()
	return btcec.NewPublicKey(&r.X, &r.Y)
}

func neg(p *btcec.PublicKey) *btcec.PublicKey {
	var jp btcec.JacobianPoint
	p.AsJacobian(&jp)
	jp.Y.Negate(1).Normalize()
	return btcec.NewPublicKey(&jp.X, &jp.Y)
}

// Blind returns B_ = Y + rG for secret x (NUT-00).
func Blind(secret []byte, r *btcec.PrivateKey) (*btcec.PublicKey, error) {
	y, err := HashToCurve(secret)
	if err != nil {
		return nil, err
	}
	return add(y, r.PubKey()), nil
}

// Unblind returns C = C_ - rK.
func Unblind(cBlind *btcec.PublicKey, r *btcec.PrivateKey, mintKey *btcec.PublicKey) *btcec.PublicKey {
	return add(cBlind, neg(mul(&r.Key, mintKey)))
}

// SignBlinded is the mint side (C_ = kB_), used only in tests.
func SignBlinded(b *btcec.PublicKey, k *btcec.PrivateKey) *btcec.PublicKey { return mul(&k.Key, b) }

var curveN = btcec.S256().N

// DeriveV2 returns the NUT-13 secret (hex string, as used in proofs) and the
// blinding factor for keyset IDs with version byte 01 (HMAC-SHA256 KDF).
func DeriveV2(seed []byte, keysetID string, counter uint64) (secret string, r *btcec.PrivateKey, err error) {
	kid, err := hex.DecodeString(keysetID)
	if err != nil || len(kid) == 0 || kid[0] != 0x01 {
		return "", nil, fmt.Errorf("cashu: keyset %q is not a version-01 keyset", keysetID)
	}
	msg := append([]byte("Cashu_KDF_HMAC_SHA256"), kid...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	msg = append(msg, c[:]...)
	m := hmac.New(sha256.New, seed)
	m.Write(append(append([]byte{}, msg...), 0x00))
	s := m.Sum(nil)
	m = hmac.New(sha256.New, seed)
	m.Write(append(append([]byte{}, msg...), 0x01))
	rb := new(big.Int).SetBytes(m.Sum(nil))
	rb.Mod(rb, curveN)
	if rb.Sign() == 0 {
		return "", nil, errors.New("cashu: r == 0")
	}
	var buf [32]byte
	rb.FillBytes(buf[:])
	r, _ = btcec.PrivKeyFromBytes(buf[:])
	return hex.EncodeToString(s), r, nil
}

// MintQuoteMessage is the NUT-20 message hash a locked mint quote is signed over.
func MintQuoteMessage(quote string, outputs []BlindedMessage) ([]byte, error) {
	msg := []byte("Cashu_MintQuoteSig_v1")
	lp := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		msg = append(append(msg, l[:]...), b...)
	}
	lp([]byte(quote))
	for _, o := range outputs {
		lp(new(big.Int).SetUint64(o.Amount).Bytes()) // minimal big-endian; 0 -> empty
		b, err := hex.DecodeString(o.B)
		if err != nil {
			return nil, err
		}
		lp(b)
	}
	h := sha256.Sum256(msg)
	return h[:], nil
}

// MintQuoteMessageLegacy is the original NUT-20 message, still required by
// some mints (e.g. cdk 0.17): sha256(quote || B_0 || B_1 ...), B_ as hex text.
func MintQuoteMessageLegacy(quote string, outputs []BlindedMessage) []byte {
	msg := []byte(quote)
	for _, o := range outputs {
		msg = append(msg, o.B...)
	}
	h := sha256.Sum256(msg)
	return h[:]
}

// SignMintQuoteLegacy signs the legacy NUT-20 message.
func SignMintQuoteLegacy(sk *btcec.PrivateKey, quote string, outputs []BlindedMessage) (string, error) {
	sig, err := schnorr.Sign(sk, MintQuoteMessageLegacy(quote, outputs))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// SignMintQuote returns the BIP-340 signature hex for a NUT-20 locked quote.
func SignMintQuote(sk *btcec.PrivateKey, quote string, outputs []BlindedMessage) (string, error) {
	h, err := MintQuoteMessage(quote, outputs)
	if err != nil {
		return "", err
	}
	sig, err := schnorr.Sign(sk, h)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// Split decomposes an amount into powers of two (ascending).
func Split(amount uint64) []uint64 {
	var out []uint64
	for b := uint64(1); amount > 0; b <<= 1 {
		if amount&b != 0 {
			out = append(out, b)
			amount &^= b
		}
	}
	return out
}
