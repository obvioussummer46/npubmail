// SPDX-License-Identifier: MIT

package cashu

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/pbkdf2"
)

func hx(s string) []byte { b, _ := hex.DecodeString(s); return b }

// Vectors from cashubtc/nuts tests/00-tests.md.
func TestHashToCurve(t *testing.T) {
	for msg, want := range map[string]string{
		"0000000000000000000000000000000000000000000000000000000000000000": "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725",
		"0000000000000000000000000000000000000000000000000000000000000001": "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf",
		"0000000000000000000000000000000000000000000000000000000000000002": "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f",
	} {
		p, err := HashToCurve(hx(msg))
		if err != nil || hex.EncodeToString(p.SerializeCompressed()) != want {
			t.Fatalf("hash_to_curve(%s) = %x", msg, p.SerializeCompressed())
		}
	}
}

func TestBlind(t *testing.T) {
	for _, v := range [][3]string{
		{"d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6", "99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a", "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d"},
		{"f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60", "f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50", "029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763"},
	} {
		r, _ := btcec.PrivKeyFromBytes(hx(v[1]))
		B, err := Blind(hx(v[0]), r)
		if err != nil || hex.EncodeToString(B.SerializeCompressed()) != v[2] {
			t.Fatalf("blind: got %x want %s", B.SerializeCompressed(), v[2])
		}
	}
	k, _ := btcec.PrivKeyFromBytes(hx("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"))
	B, _ := parsePub("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
	if got := hex.EncodeToString(SignBlinded(B, k).SerializeCompressed()); got != "0398bc70ce8184d27ba89834d19f5199c84443c31131e48d3c1214db24247d005d" {
		t.Fatalf("sign: %s", got)
	}
}

func TestUnblindRoundTrip(t *testing.T) {
	k, _ := btcec.NewPrivateKey()
	r, _ := btcec.NewPrivateKey()
	sec := []byte("some secret")
	B, _ := Blind(sec, r)
	C := Unblind(SignBlinded(B, k), r, k.PubKey())
	Y, _ := HashToCurve(sec)
	if !C.IsEqual(SignBlinded(Y, k)) {
		t.Fatal("C != kY")
	}
}

// Vectors from tests/13-tests.md, "Version 2: Secret derivation".
func TestDeriveV2(t *testing.T) {
	seed := pbkdf2.Key([]byte("half depart obvious quality work element tank gorilla view sugar picture humble"), []byte("mnemonic"), 2048, 64, sha512.New)
	kid := "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a"
	secrets := []string{"db5561a07a6e6490f8dadeef5be4e92f7cebaecf2f245356b5b2a4ec40687298", "b70e7b10683da3bf1cdf0411206f8180c463faa16014663f39f2529b2fda922e", "78a7ac32ccecc6b83311c6081b89d84bb4128f5a0d0c5e1af081f301c7a513f5", "094a2b6c63bfa7970bc09cda0e1cfc9cd3d7c619b8e98fabcfc60aea9e4963e5", "5e89fc5d30d0bf307ddf0a3ac34aa7a8ee3702169dafa3d3fe1d0cae70ecd5ef"}
	rs := []string{"6d26181a3695e32e9f88b80f039ba1ae2ab5a200ad4ce9dbc72c6d3769f2b035", "bde4354cee75545bea1a2eee035a34f2d524cee2bb01613823636e998386952e", "f40cc1218f085b395c8e1e5aaa25dccc851be3c6c7526a0f4e57108f12d6dac4", "099ed70fc2f7ac769bc20b2a75cb662e80779827b7cc358981318643030577d0", "5550337312d223ba62e3f75cfe2ab70477b046d98e3e71804eade3956c7b98cf"}
	for i := range secrets {
		s, r, err := DeriveV2(seed, kid, uint64(i))
		if err != nil || s != secrets[i] || hex.EncodeToString(r.Serialize()) != rs[i] {
			t.Fatalf("counter %d: %s %x %v", i, s, r.Serialize(), err)
		}
	}
	if _, _, err := DeriveV2(seed, "009a1f293253e41e", 0); err == nil {
		t.Fatal("v1 keyset accepted")
	}
}

func TestSplit(t *testing.T) {
	if got := Split(13); len(got) != 3 || got[0] != 1 || got[1] != 4 || got[2] != 8 {
		t.Fatal(got)
	}
	if len(Split(0)) != 0 {
		t.Fatal("0")
	}
}

func TestMintQuoteMessageAmountEncoding(t *testing.T) {
	// amount 0 -> empty, 256 -> 0x0100 (NUT-20 canonical minimal bytes)
	a, _ := MintQuoteMessage("q", []BlindedMessage{{Amount: 0, B: "02"}})
	b, _ := MintQuoteMessage("q", []BlindedMessage{{Amount: 256, B: "02"}})
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("amount not committed")
	}
}

// Cross-checked against Nutshell 0.21 cashu.core.nuts.nut20.construct_message.
func TestMintQuoteMessageNutshell(t *testing.T) {
	h, err := MintQuoteMessage("9d745270-1405-46de-b5c5-e2762b4f5e00", []BlindedMessage{
		{Amount: 0, B: "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"},
		{Amount: 256, B: "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d"},
	})
	if err != nil || hex.EncodeToString(h) != "662809088e998629989be130e5734eb98203b7062486a0f203185ce00a5a065b" {
		t.Fatalf("got %x", h)
	}
}
