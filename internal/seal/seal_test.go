package seal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestRoundTrip(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	big := bytes.Repeat([]byte("Ä mail body line\n"), 20000) // > 64 KiB
	for _, pt := range [][]byte{[]byte("code 482913"), big, {}} {
		s, err := Seal(pk, pt)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s, "482913") {
			t.Fatal("plaintext visible")
		}
		got, err := Open(sk, s)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("round trip failed: %v", err)
		}
	}
}

func TestWrongKeyAndTamper(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	s, _ := Seal(pk, []byte("secret"))
	if _, err := Open(nostr.GeneratePrivateKey(), s); err == nil {
		t.Fatal("other key decrypted")
	}
	b := []byte(s)
	b[len(b)-3] ^= 1
	if _, err := Open(sk, string(b)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	s2, _ := Seal(pk, []byte("secret"))
	if s == s2 {
		t.Fatal("ciphertext not randomized")
	}
}
