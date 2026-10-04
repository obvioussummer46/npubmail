// SPDX-License-Identifier: MIT

package seal

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Vector is one published test case (docs/SEAL.md). Independent
// implementations should reproduce conversation_key and sealed exactly and
// open sealed back to plaintext.
type Vector struct {
	Comment         string `json:"comment"`
	OwnerSecret     string `json:"owner_secret"`
	OwnerPubkey     string `json:"owner_pubkey"`
	EphemeralSecret string `json:"ephemeral_secret"`
	EphemeralPubkey string `json:"ephemeral_pubkey"`
	SharedX         string `json:"shared_x"`
	ConversationKey string `json:"conversation_key"`
	Nonce           string `json:"nonce"`
	Plaintext       string `json:"plaintext"`
	Sealed          string `json:"sealed"`
}

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

func makeVectors(t *testing.T) []Vector {
	cases := []struct{ comment, owner, eph, nonce, pt string }{
		{"header part (\"sealed\")",
			"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000002",
			"000102030405060708090a0b0c0d0e0f1011121314151617",
			`{"to":"hermes@npubmail.com","mail_from":"bounce@example.com","from":"Example <noreply@example.com>","subject":"Your code","auth":{"spf":"pass","dkim":["example.com"],"aligned":true},"codes":["482913"],"warnings":[]}`},
		{"body part (\"sealed_body\"), non-ASCII text",
			"7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
			"5c0c523f52a5a6ad7cf5e3eb9e2b8f1d6f3c5d2b6e8a4c0f1e2d3c4b5a697887",
			"ffeeddccbbaa99887766554433221100ffeeddccbbaa9988",
			`{"text":"Grüße aus Frankfurt — code 123456\n","links":[{"url":"https://example.com/verify?t=abc","action":true}]}`},
		{"empty plaintext",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
			"0000000000000000000000000000000000000000000000000000000000000003",
			"000000000000000000000000000000000000000000000000",
			""},
	}
	var out []Vector
	for _, c := range cases {
		opk, _ := nostr.GetPublicKey(c.owner)
		epk, _ := nostr.GetPublicKey(c.eph)
		nonce, _ := hex.DecodeString(c.nonce)
		s, err := sealWith(c.eph, nonce, opk, []byte(c.pt))
		if err != nil {
			t.Fatal(err)
		}
		ck, _ := nip44.GenerateConversationKey(opk, c.eph)
		sx, err := sharedX(c.eph, opk)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Vector{c.comment, c.owner, opk, c.eph, epk, sx, hex.EncodeToString(ck[:]), c.nonce, c.pt, s})
	}
	return out
}

func TestVectors(t *testing.T) {
	got := makeVectors(t)
	path := "testdata/vectors.json"
	if *update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []Vector
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("vector count %d != %d", len(want), len(got))
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("vector %d changed: format drift would break third-party decryptors", i)
		}
		pt, err := Open(v.OwnerSecret, v.Sealed)
		if err != nil || string(pt) != v.Plaintext {
			t.Fatalf("vector %d does not open: %v", i, err)
		}
	}
}

// sharedX is the raw ECDH x coordinate (the HKDF input), published so
// implementers can locate a mismatch step by step.
func sharedX(secHex, xonlyPubHex string) (string, error) {
	sb, err := hex.DecodeString(secHex)
	if err != nil {
		return "", err
	}
	pb, err := hex.DecodeString("02" + xonlyPubHex)
	if err != nil {
		return "", err
	}
	pub, err := btcec.ParsePubKey(pb)
	if err != nil {
		return "", err
	}
	priv, _ := btcec.PrivKeyFromBytes(sb)
	var p, r btcec.JacobianPoint
	pub.AsJacobian(&p)
	btcec.ScalarMultNonConst(&priv.Key, &p, &r)
	r.ToAffine()
	x := r.X.Bytes()
	return hex.EncodeToString(x[:]), nil
}
