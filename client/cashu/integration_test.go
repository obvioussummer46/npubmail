// SPDX-License-Identifier: MIT

package cashu

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestAgainstMint runs the whole wallet against a real Cashu mint with a fake
// Lightning backend (Nutshell FakeWallet): CASHU_TEST_MINT=http://127.0.0.1:3339
// invoice makes an external test invoice (CASHU_TEST_INVOICE_CMD <sats>).
func invoice(t *testing.T, sats int) string {
	f := strings.Fields(os.Getenv("CASHU_TEST_INVOICE_CMD"))
	if len(f) == 0 {
		t.Skip("CASHU_TEST_INVOICE_CMD not set")
	}
	out, err := exec.Command(f[0], append(f[1:], strconv.Itoa(sats))...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestAgainstMint(t *testing.T) {
	url := os.Getenv("CASHU_TEST_MINT")
	if url == "" {
		t.Skip("CASHU_TEST_MINT not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sk, _ := btcec.NewPrivateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := Create(path, sk.Serialize(), url)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMint(url)

	// 1. receive 64 sats via a NUT-20 quote locked to our key
	lockPub := hex.EncodeToString(sk.PubKey().SerializeCompressed())
	q, err := m.NewMintQuote(ctx, 64, lockPub)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ { // FakeWallet marks it paid
		st, _ := m.MintQuoteState(ctx, q.Quote)
		if st.State == "PAID" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	// a stranger cannot mint a locked quote
	other, _ := btcec.NewPrivateKey()
	w2, _ := Create(filepath.Join(dir, "other.json"), other.Serialize(), url)
	if _, err := w2.MintPaidQuote(ctx, url, q.Quote, 64, true); err == nil {
		t.Fatal("foreign key minted a locked quote")
	}
	got, err := w.MintPaidQuote(ctx, url, q.Quote, 64, true)
	if err != nil || got != 64 || w.Balance() != 64 {
		t.Fatalf("mint: got %d bal %d err %v", got, w.Balance(), err)
	}
	if again, _ := w.MintPaidQuote(ctx, url, q.Quote, 64, true); again != 0 {
		t.Fatal("double claim")
	}

	// 2. pay an invoice (FakeWallet invoice from another mint quote) with change
	res, err := w.Pay(ctx, invoice(t, 21))
	if err != nil || !res.Paid {
		t.Fatalf("pay: %+v %v", res, err)
	}
	t.Logf("paid 21: fee %d, balance %d", res.Fee, res.Balance)
	if res.Balance != 64-21-res.Fee {
		t.Fatalf("balance %d after paying 21 + fee %d", res.Balance, res.Fee)
	}

	// 3. limits
	w.S.Limits = Limits{PerPayment: 10, PerDay: 1000}
	if _, err := w.Pay(ctx, invoice(t, 20)); err == nil {
		t.Fatal("limit not enforced")
	} else if _, ok := err.(*LimitError); !ok {
		t.Fatalf("want LimitError, got %v", err)
	}
	if w.Balance() != res.Balance {
		t.Fatal("limit refusal changed the balance")
	}

	// 4. lose the wallet file, restore from the key alone
	before := w.Balance()
	_ = os.Remove(path)
	w3, err := Create(path, sk.Serialize(), url)
	if err != nil {
		t.Fatal(err)
	}
	n, err := w3.Restore(ctx, url)
	if err != nil || n != before {
		t.Fatalf("restore: %d (want %d) %v", n, before, err)
	}
	// restored proofs are spendable and counters moved past used ones
	if r, err := w3.Pay(ctx, invoice(t, 5)); err != nil || !r.Paid {
		t.Fatalf("pay after restore: %v", err)
	}
}
