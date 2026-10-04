// SPDX-License-Identifier: MIT

package cashu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Wire types (NUT-00..09).

type BlindedMessage struct {
	Amount uint64 `json:"amount"`
	ID     string `json:"id"`
	B      string `json:"B_"`
}

type BlindSignature struct {
	Amount uint64 `json:"amount"`
	ID     string `json:"id"`
	C      string `json:"C_"`
}

type Proof struct {
	Amount uint64 `json:"amount"`
	ID     string `json:"id"`
	Secret string `json:"secret"`
	C      string `json:"C"`
}

type Keyset struct {
	ID          string `json:"id"`
	Unit        string `json:"unit"`
	Active      bool   `json:"active"`
	InputFeePPK uint64 `json:"input_fee_ppk"`
}

type KeysetKeys struct {
	ID   string            `json:"id"`
	Unit string            `json:"unit"`
	Keys map[string]string `json:"keys"`
	// Present on some mints; part of the v2 keyset id preimage.
	FinalExpiry *int64 `json:"final_expiry,omitempty"`
}

type MintQuote struct {
	Quote   string `json:"quote"`
	Request string `json:"request"`
	State   string `json:"state"` // UNPAID, PAID, ISSUED
	Amount  uint64 `json:"amount,omitempty"`
	Expiry  int64  `json:"expiry"`
	Pubkey  string `json:"pubkey,omitempty"`
}

type MeltQuote struct {
	Quote      string           `json:"quote"`
	Amount     uint64           `json:"amount"`
	FeeReserve uint64           `json:"fee_reserve"`
	State      string           `json:"state"` // UNPAID, PENDING, PAID
	Expiry     int64            `json:"expiry"`
	Preimage   string           `json:"payment_preimage,omitempty"`
	Change     []BlindSignature `json:"change,omitempty"`
}

// MintError is an error answer from a mint ({"detail": ..., "code": ...}).
type MintError struct {
	Status int
	Detail string
	Code   int
}

func (e *MintError) Error() string {
	return fmt.Sprintf("mint: %d %s (code %d)", e.Status, e.Detail, e.Code)
}

// Mint is a client for one mint.
type Mint struct {
	URL  string
	HTTP *http.Client
}

func NewMint(url string) *Mint {
	return &Mint{URL: strings.TrimRight(url, "/"), HTTP: &http.Client{Timeout: 90 * time.Second}}
}

func (m *Mint) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.URL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "npubmail-wallet")
	res, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		var e struct {
			Detail string `json:"detail"`
			Code   int    `json:"code"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Detail == "" {
			e.Detail = strings.TrimSpace(string(b))
		}
		return &MintError{res.StatusCode, e.Detail, e.Code}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func (m *Mint) Keysets(ctx context.Context) ([]Keyset, error) {
	var r struct{ Keysets []Keyset }
	return r.Keysets, m.do(ctx, "GET", "/v1/keysets", nil, &r)
}

func (m *Mint) Keys(ctx context.Context, id string) (*KeysetKeys, error) {
	var r struct{ Keysets []KeysetKeys }
	if err := m.do(ctx, "GET", "/v1/keys/"+id, nil, &r); err != nil {
		return nil, err
	}
	for _, k := range r.Keysets {
		if k.ID == id {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("mint: keyset %s not returned", id)
}

func (m *Mint) NewMintQuote(ctx context.Context, amount uint64, pubkey string) (*MintQuote, error) {
	var q MintQuote
	in := map[string]any{"amount": amount, "unit": "sat"}
	if pubkey != "" {
		in["pubkey"] = pubkey
	}
	return &q, m.do(ctx, "POST", "/v1/mint/quote/bolt11", in, &q)
}

func (m *Mint) MintQuoteState(ctx context.Context, id string) (*MintQuote, error) {
	var q MintQuote
	return &q, m.do(ctx, "GET", "/v1/mint/quote/bolt11/"+id, nil, &q)
}

func (m *Mint) MintTokens(ctx context.Context, quote string, outputs []BlindedMessage, sig string) ([]BlindSignature, error) {
	in := map[string]any{"quote": quote, "outputs": outputs}
	if sig != "" {
		in["signature"] = sig
	}
	var r struct{ Signatures []BlindSignature }
	return r.Signatures, m.do(ctx, "POST", "/v1/mint/bolt11", in, &r)
}

func (m *Mint) Swap(ctx context.Context, inputs []Proof, outputs []BlindedMessage) ([]BlindSignature, error) {
	var r struct{ Signatures []BlindSignature }
	return r.Signatures, m.do(ctx, "POST", "/v1/swap", map[string]any{"inputs": inputs, "outputs": outputs}, &r)
}

func (m *Mint) NewMeltQuote(ctx context.Context, bolt11 string) (*MeltQuote, error) {
	var q MeltQuote
	return &q, m.do(ctx, "POST", "/v1/melt/quote/bolt11", map[string]any{"request": bolt11, "unit": "sat"}, &q)
}

func (m *Mint) MeltQuoteState(ctx context.Context, id string) (*MeltQuote, error) {
	var q MeltQuote
	return &q, m.do(ctx, "GET", "/v1/melt/quote/bolt11/"+id, nil, &q)
}

func (m *Mint) Melt(ctx context.Context, quote string, inputs []Proof, outputs []BlindedMessage) (*MeltQuote, error) {
	if outputs == nil {
		outputs = []BlindedMessage{}
	}
	var q MeltQuote
	return &q, m.do(ctx, "POST", "/v1/melt/bolt11", map[string]any{"quote": quote, "inputs": inputs, "outputs": outputs}, &q)
}

// CheckState returns UNSPENT, PENDING or SPENT per Y (hex of hash_to_curve(secret)).
func (m *Mint) CheckState(ctx context.Context, ys []string) (map[string]string, error) {
	var r struct {
		States []struct{ Y, State string }
	}
	if err := m.do(ctx, "POST", "/v1/checkstate", map[string]any{"Ys": ys}, &r); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, s := range r.States {
		out[s.Y] = s.State
	}
	return out, nil
}

func (m *Mint) Restore(ctx context.Context, outputs []BlindedMessage) ([]BlindedMessage, []BlindSignature, error) {
	var r struct {
		Outputs    []BlindedMessage `json:"outputs"`
		Signatures []BlindSignature `json:"signatures"`
		Promises   []BlindSignature `json:"promises"` // older mints
	}
	if err := m.do(ctx, "POST", "/v1/restore", map[string]any{"outputs": outputs}, &r); err != nil {
		return nil, nil, err
	}
	if len(r.Signatures) == 0 {
		r.Signatures = r.Promises
	}
	return r.Outputs, r.Signatures, nil
}
