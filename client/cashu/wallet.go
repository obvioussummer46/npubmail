// SPDX-License-Identifier: MIT

package cashu

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// SeedFromNostrKey derives the wallet seed from the agent's Nostr secret key,
// so one key backs up both mail and money:
// seed = HMAC-SHA512(key = "npubmail-cashu-seed-v1", msg = 32-byte secret).
func SeedFromNostrKey(sk []byte) []byte {
	m := hmac.New(sha512.New, []byte("npubmail-cashu-seed-v1"))
	m.Write(sk)
	return m.Sum(nil)
}

// Limits cap spending, so a prompt injection cannot drain the wallet.
type Limits struct {
	PerPayment uint64 `json:"per_payment_sats"`
	PerDay     uint64 `json:"per_day_sats"`
}

var DefaultLimits = Limits{PerPayment: 100, PerDay: 1000}

type spend struct {
	At   int64  `json:"at"`
	Sats uint64 `json:"sats"`
}

// State is the wallet file (mode 600). Proofs are bearer money: anyone with
// this file can spend them.
type State struct {
	Version  int                `json:"version"`
	Mint     string             `json:"mint"`
	Counters map[string]uint64  `json:"counters"` // keyset id -> next NUT-13 counter
	Proofs   map[string][]Proof `json:"proofs"`   // mint URL -> proofs
	Claimed  map[string]int64   `json:"claimed"`  // "mint|quote" -> time, already minted
	Spends   []spend            `json:"spends"`
	Limits   Limits             `json:"limits"`
}

// Wallet is a deterministic Cashu wallet over a State file.
type Wallet struct {
	Path  string
	seed  []byte
	sk    *btcec.PrivateKey // Nostr key, signs NUT-20 locked quotes
	S     State
	mu    sync.Mutex
	mints map[string]*Mint
	keys  map[string]*KeysetKeys
	Now   func() time.Time
}

var ErrNoWallet = errors.New("wallet not set up (run wallet setup); it is optional — any Lightning wallet can pay npubmail invoices")

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "npubmail", "wallet.json")
}

// Open loads an existing wallet. nostrSK is the 32-byte secret key.
func Open(path string, nostrSK []byte) (*Wallet, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoWallet
	}
	if err != nil {
		return nil, err
	}
	w := newWallet(path, nostrSK)
	if err := json.Unmarshal(b, &w.S); err != nil {
		return nil, fmt.Errorf("wallet file: %w", err)
	}
	w.fill()
	return w, nil
}

// Create writes a new, empty wallet file (refuses to overwrite).
func Create(path string, nostrSK []byte, mint string) (*Wallet, error) {
	if _, err := os.Stat(path); err == nil {
		return Open(path, nostrSK)
	}
	w := newWallet(path, nostrSK)
	w.S = State{Version: 1, Mint: mint, Limits: DefaultLimits}
	w.fill()
	return w, w.Save()
}

func newWallet(path string, sk []byte) *Wallet {
	priv, _ := btcec.PrivKeyFromBytes(sk)
	return &Wallet{Path: path, seed: SeedFromNostrKey(sk), sk: priv, mints: map[string]*Mint{}, keys: map[string]*KeysetKeys{}, Now: time.Now}
}

func (w *Wallet) fill() {
	if w.S.Counters == nil {
		w.S.Counters = map[string]uint64{}
	}
	if w.S.Proofs == nil {
		w.S.Proofs = map[string][]Proof{}
	}
	if w.S.Claimed == nil {
		w.S.Claimed = map[string]int64{}
	}
	if w.S.Limits.PerPayment == 0 && w.S.Limits.PerDay == 0 {
		w.S.Limits = DefaultLimits
	}
}

// Save writes atomically with mode 600.
func (w *Wallet) Save() error {
	if err := os.MkdirAll(filepath.Dir(w.Path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(w.S, "", " ")
	if err != nil {
		return err
	}
	tmp := w.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.Path)
}

func (w *Wallet) mint(url string) *Mint {
	if m := w.mints[url]; m != nil {
		return m
	}
	m := NewMint(url)
	w.mints[url] = m
	return m
}

// Balance sums stored proofs (all mints).
func (w *Wallet) Balance() uint64 {
	var n uint64
	for k, ps := range w.S.Proofs {
		if _, _, pending := splitPending(k); pending {
			continue
		}
		for _, p := range ps {
			n += p.Amount
		}
	}
	return n
}

func (w *Wallet) BalanceAt(mint string) uint64 {
	var n uint64
	for _, p := range w.S.Proofs[mint] {
		n += p.Amount
	}
	return n
}

// activeKeyset returns the active sat keyset (version 01) with verified keys.
func (w *Wallet) activeKeyset(ctx context.Context, mintURL string) (*KeysetKeys, uint64, error) {
	m := w.mint(mintURL)
	kss, err := m.Keysets(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, ks := range kss {
		if ks.Unit == "sat" && ks.Active && len(ks.ID) >= 2 && ks.ID[:2] == "01" {
			k, err := w.keyset(ctx, mintURL, ks.ID, ks.InputFeePPK)
			return k, ks.InputFeePPK, err
		}
	}
	return nil, 0, fmt.Errorf("mint %s has no active version-01 sat keyset", mintURL)
}

func (w *Wallet) keyset(ctx context.Context, mintURL, id string, fee uint64) (*KeysetKeys, error) {
	if k := w.keys[id]; k != nil {
		return k, nil
	}
	k, err := w.mint(mintURL).Keys(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := VerifyKeysetID(k, fee); err != nil {
		return nil, err
	}
	w.keys[id] = k
	return k, nil
}

// feeFor is the NUT-02 input fee for spending these proofs.
func (w *Wallet) feeFor(ctx context.Context, mintURL string, ps []Proof) (uint64, error) {
	kss, err := w.mint(mintURL).Keysets(ctx)
	if err != nil {
		return 0, err
	}
	ppk := map[string]uint64{}
	for _, k := range kss {
		ppk[k.ID] = k.InputFeePPK
	}
	var sum uint64
	for _, p := range ps {
		sum += ppk[p.ID]
	}
	return (sum + 999) / 1000, nil
}

type pendingOutput struct {
	msg    BlindedMessage
	secret string
	r      *btcec.PrivateKey
}

// outputs derives deterministic blinded messages for the amounts and
// advances (and persists) the keyset counter before they are sent, so a crash
// after the mint signs can be recovered with Restore.
func (w *Wallet) outputs(ks *KeysetKeys, amounts []uint64) ([]pendingOutput, error) {
	out := make([]pendingOutput, 0, len(amounts))
	ctr := w.S.Counters[ks.ID]
	for _, a := range amounts {
		sec, r, err := DeriveV2(w.seed, ks.ID, ctr)
		if err != nil {
			return nil, err
		}
		ctr++
		B, err := Blind([]byte(sec), r)
		if err != nil {
			return nil, err
		}
		out = append(out, pendingOutput{BlindedMessage{a, ks.ID, hex.EncodeToString(B.SerializeCompressed())}, sec, r})
	}
	w.S.Counters[ks.ID] = ctr
	return out, w.Save()
}

func msgs(po []pendingOutput) []BlindedMessage {
	m := make([]BlindedMessage, len(po))
	for i, p := range po {
		m[i] = p.msg
	}
	return m
}

// unblind turns signatures into proofs. With blank outputs (melt change) the
// mint returns fewer signatures, in output order.
func (w *Wallet) unblind(ks *KeysetKeys, po []pendingOutput, sigs []BlindSignature) ([]Proof, error) {
	var out []Proof
	for i, s := range sigs {
		if i >= len(po) {
			break
		}
		kh, ok := ks.Keys[strconv.FormatUint(s.Amount, 10)]
		if !ok {
			return nil, fmt.Errorf("mint signed unknown amount %d", s.Amount)
		}
		K, err := parsePub(kh)
		if err != nil {
			return nil, err
		}
		Cb, err := parsePub(s.C)
		if err != nil {
			return nil, err
		}
		C := Unblind(Cb, po[i].r, K)
		out = append(out, Proof{Amount: s.Amount, ID: s.ID, Secret: po[i].secret, C: hex.EncodeToString(C.SerializeCompressed())})
	}
	return out, nil
}

// MintQuote mints ecash for a paid quote at mintURL. lockedTo, if set, is the
// NUT-20 pubkey the quote was locked to (must be our Nostr key).
func (w *Wallet) MintPaidQuote(ctx context.Context, mintURL, quote string, amount uint64, locked bool) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := mintURL + "|" + quote
	if _, done := w.S.Claimed[key]; done {
		return 0, nil
	}
	ks, _, err := w.activeKeyset(ctx, mintURL)
	if err != nil {
		return 0, err
	}
	po, err := w.outputs(ks, Split(amount))
	if err != nil {
		return 0, err
	}
	sig := ""
	if locked {
		if sig, err = SignMintQuote(w.sk, quote, msgs(po)); err != nil {
			return 0, err
		}
	}
	sigs, err := w.mint(mintURL).MintTokens(ctx, quote, msgs(po), sig)
	var me0 *MintError
	if locked && errors.As(err, &me0) && me0.Code == 20008 {
		// mint predates the current NUT-20 message format: retry with the legacy one
		if sig, err = SignMintQuoteLegacy(w.sk, quote, msgs(po)); err != nil {
			return 0, err
		}
		sigs, err = w.mint(mintURL).MintTokens(ctx, quote, msgs(po), sig)
	}
	if err != nil {
		var me *MintError
		if errors.As(err, &me) && (me.Code == 20002 || me.Code == 20007) { // already issued / expired
			w.S.Claimed[key] = w.Now().Unix()
			_ = w.Save()
			return 0, nil
		}
		return 0, err
	}
	ps, err := w.unblind(ks, po, sigs)
	if err != nil {
		return 0, err
	}
	w.S.Proofs[mintURL] = append(w.S.Proofs[mintURL], ps...)
	w.S.Claimed[key] = w.Now().Unix()
	var got uint64
	for _, p := range ps {
		got += p.Amount
	}
	return got, w.Save()
}

// spentToday sums spends in the last 24 h.
func (w *Wallet) spentToday() uint64 {
	cut := w.Now().Add(-24 * time.Hour).Unix()
	var n uint64
	keep := w.S.Spends[:0]
	for _, s := range w.S.Spends {
		if s.At >= cut {
			n += s.Sats
			keep = append(keep, s)
		}
	}
	w.S.Spends = keep
	return n
}

// LimitError explains which cap a payment would break.
type LimitError struct{ Msg string }

func (e *LimitError) Error() string { return e.Msg }

// CheckLimits returns an error if paying total sats would break a cap.
func (w *Wallet) CheckLimits(total uint64) error {
	if total > w.S.Limits.PerPayment {
		return &LimitError{fmt.Sprintf("payment of %d sats exceeds the per-payment limit of %d sats (the wallet owner can raise it with: npubmail wallet limits)", total, w.S.Limits.PerPayment)}
	}
	if used := w.spentToday(); used+total > w.S.Limits.PerDay {
		return &LimitError{fmt.Sprintf("payment of %d sats would exceed the daily limit of %d sats (%d used in the last 24 h)", total, w.S.Limits.PerDay, used)}
	}
	return nil
}

// PayResult reports a Lightning payment from the wallet.
type PayResult struct {
	Paid      bool   `json:"paid"`
	Amount    uint64 `json:"amount_sats"`
	Fee       uint64 `json:"fee_sats"`
	Preimage  string `json:"preimage,omitempty"`
	Balance   uint64 `json:"balance_sats"`
	State     string `json:"state"`
	MeltQuote string `json:"melt_quote"`
}

// selectProofs picks proofs (largest first) covering at least target.
func selectProofs(ps []Proof, target uint64) (sel, rest []Proof, ok bool) {
	sorted := append([]Proof(nil), ps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Amount > sorted[j].Amount })
	var sum uint64
	for _, p := range sorted {
		if sum < target {
			sel = append(sel, p)
			sum += p.Amount
		} else {
			rest = append(rest, p)
		}
	}
	return sel, rest, sum >= target
}

// Pay pays a bolt11 invoice from the wallet's default mint (NUT-05 melt).
func (w *Wallet) Pay(ctx context.Context, bolt11 string) (*PayResult, error) {
	return w.PayExact(ctx, bolt11, 0)
}

// PayExact is Pay, refusing unless the invoice is for exactly expect sats
// (0 = any amount).
func (w *Wallet) PayExact(ctx context.Context, bolt11 string, expect uint64) (*PayResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	mintURL := w.S.Mint
	m := w.mint(mintURL)
	q, err := m.NewMeltQuote(ctx, bolt11)
	if err != nil {
		return nil, err
	}
	if expect != 0 && q.Amount != expect {
		return nil, fmt.Errorf("invoice is for %d sats, expected %d", q.Amount, expect)
	}
	ks, _, err := w.activeKeyset(ctx, mintURL)
	if err != nil {
		return nil, err
	}
	need := q.Amount + q.FeeReserve
	// Input fees depend on which proofs are used; iterate to a fixed point.
	var inputs, rest []Proof
	for i := 0; i < 4; i++ {
		var ok bool
		inputs, rest, ok = selectProofs(w.S.Proofs[mintURL], need)
		if !ok {
			return nil, fmt.Errorf("insufficient balance: need %d sats (amount %d + fee reserve %d), have %d", need, q.Amount, q.FeeReserve, w.BalanceAt(mintURL))
		}
		f, err := w.feeFor(ctx, mintURL, inputs)
		if err != nil {
			return nil, err
		}
		if q.Amount+q.FeeReserve+f == need {
			break
		}
		need = q.Amount + q.FeeReserve + f
	}
	if err := w.CheckLimits(need); err != nil {
		return nil, err
	}
	var sum uint64
	for _, p := range inputs {
		sum += p.Amount
	}
	// Swap to exact denominations first if we would overpay by more than the
	// change outputs can return.
	if sum > need {
		swapFee, err := w.feeFor(ctx, mintURL, inputs)
		if err != nil {
			return nil, err
		}
		if sum < need+swapFee {
			return nil, fmt.Errorf("insufficient balance for swap fee")
		}
		keep := sum - need - swapFee
		amts := append(Split(need), Split(keep)...)
		po, err := w.outputs(ks, amts)
		if err != nil {
			return nil, err
		}
		sigs, err := m.Swap(ctx, inputs, msgs(po))
		if err != nil {
			return nil, err
		}
		ps, err := w.unblind(ks, po, sigs)
		if err != nil {
			return nil, err
		}
		n := len(Split(need))
		w.S.Proofs[mintURL] = append(rest, ps[n:]...)
		inputs = ps[:n]
		if err := w.Save(); err != nil {
			return nil, err
		}
		rest = w.S.Proofs[mintURL]
	}
	// NUT-08 blank outputs for fee change.
	nBlank := 0
	if q.FeeReserve > 0 {
		nBlank = int(math.Max(math.Ceil(math.Log2(float64(q.FeeReserve))), 1))
	}
	blank, err := w.outputs(ks, make([]uint64, nBlank))
	if err != nil {
		return nil, err
	}
	// Remove inputs from the store before melting; put back on failure.
	w.S.Proofs[mintURL] = rest
	if err := w.Save(); err != nil {
		return nil, err
	}
	res, err := m.Melt(ctx, q.Quote, inputs, msgs(blank))
	if err != nil {
		// Unknown outcome: ask the mint which inputs are still unspent.
		w.restoreUnspent(ctx, mintURL, inputs)
		return nil, fmt.Errorf("payment failed: %w", err)
	}
	if res.State != "PAID" {
		if res.State == "UNPAID" {
			w.restoreUnspent(ctx, mintURL, inputs)
		} else { // PENDING: keep inputs aside until the mint settles
			w.S.Proofs[mintURL+"#pending:"+q.Quote] = inputs
			_ = w.Save()
		}
		return &PayResult{Paid: false, State: res.State, MeltQuote: q.Quote, Balance: w.Balance()}, nil
	}
	change, err := w.unblind(ks, blank, res.Change)
	if err != nil {
		return nil, err
	}
	w.S.Proofs[mintURL] = append(w.S.Proofs[mintURL], change...)
	var back uint64
	for _, c := range change {
		back += c.Amount
	}
	spent := need - back
	w.S.Spends = append(w.S.Spends, spend{w.Now().Unix(), spent})
	if err := w.Save(); err != nil {
		return nil, err
	}
	return &PayResult{Paid: true, Amount: q.Amount, Fee: spent - q.Amount, Preimage: res.Preimage, Balance: w.Balance(), State: "PAID", MeltQuote: q.Quote}, nil
}

func (w *Wallet) restoreUnspent(ctx context.Context, mintURL string, ps []Proof) {
	ys := make([]string, 0, len(ps))
	byY := map[string]Proof{}
	for _, p := range ps {
		y, err := Y(p.Secret)
		if err != nil {
			continue
		}
		ys = append(ys, y)
		byY[y] = p
	}
	st, err := w.mint(mintURL).CheckState(ctx, ys)
	if err != nil { // can't tell: keep them, a later Check will clean up
		w.S.Proofs[mintURL] = append(w.S.Proofs[mintURL], ps...)
		_ = w.Save()
		return
	}
	for y, p := range byY {
		if st[y] != "SPENT" {
			w.S.Proofs[mintURL] = append(w.S.Proofs[mintURL], p)
		}
	}
	_ = w.Save()
}

// Settle resolves payments left PENDING and drops proofs the mint reports spent.
func (w *Wallet) Settle(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for key, ps := range w.S.Proofs {
		mintURL, quote, pending := splitPending(key)
		if !pending {
			continue
		}
		q, err := w.mint(mintURL).MeltQuoteState(ctx, quote)
		if err != nil || q.State == "PENDING" {
			continue
		}
		delete(w.S.Proofs, key)
		if q.State == "PAID" {
			var n uint64
			for _, p := range ps {
				n += p.Amount
			}
			w.S.Spends = append(w.S.Spends, spend{w.Now().Unix(), n})
		} else {
			w.restoreUnspent(ctx, mintURL, ps)
		}
	}
	return w.Save()
}

func splitPending(key string) (mint, quote string, ok bool) {
	const tag = "#pending:"
	for i := 0; i+len(tag) <= len(key); i++ {
		if key[i:i+len(tag)] == tag {
			return key[:i], key[i+len(tag):], true
		}
	}
	return key, "", false
}

// Restore rebuilds proofs at mintURL from the seed alone (NUT-09 + NUT-13).
func (w *Wallet) Restore(ctx context.Context, mintURL string) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.mint(mintURL)
	kss, err := m.Keysets(ctx)
	if err != nil {
		return 0, err
	}
	have := map[string]bool{}
	for _, p := range w.S.Proofs[mintURL] {
		have[p.Secret] = true
	}
	var found []Proof
	for _, ksi := range kss {
		if ksi.Unit != "sat" || len(ksi.ID) < 2 || ksi.ID[:2] != "01" {
			continue
		}
		ks, err := w.keyset(ctx, mintURL, ksi.ID, ksi.InputFeePPK)
		if err != nil {
			return 0, err
		}
		var ctr, empty uint64
		next := uint64(0)
		for empty < 3 {
			po := make([]pendingOutput, 0, 100)
			for i := uint64(0); i < 100; i++ {
				sec, r, err := DeriveV2(w.seed, ks.ID, ctr+i)
				if err != nil {
					return 0, err
				}
				B, err := Blind([]byte(sec), r)
				if err != nil {
					return 0, err
				}
				po = append(po, pendingOutput{BlindedMessage{1, ks.ID, hex.EncodeToString(B.SerializeCompressed())}, sec, r})
			}
			outs, sigs, err := m.Restore(ctx, msgs(po))
			if err != nil {
				return 0, err
			}
			if len(sigs) == 0 {
				empty++
			} else {
				empty = 0
				byB := map[string]int{}
				for i, p := range po {
					byB[p.msg.B] = i
				}
				for i, o := range outs {
					j, ok := byB[o.B]
					if !ok || i >= len(sigs) {
						continue
					}
					ps, err := w.unblind(ks, []pendingOutput{po[j]}, []BlindSignature{sigs[i]})
					if err != nil {
						return 0, err
					}
					found = append(found, ps...)
					if ctr+uint64(j)+1 > next {
						next = ctr + uint64(j) + 1
					}
				}
			}
			ctr += 100
		}
		if next > w.S.Counters[ks.ID] {
			w.S.Counters[ks.ID] = next
		}
	}
	ys := []string{}
	byY := map[string]Proof{}
	for _, p := range found {
		if have[p.Secret] {
			continue
		}
		y, _ := Y(p.Secret)
		ys = append(ys, y)
		byY[y] = p
	}
	var added uint64
	if len(ys) > 0 {
		st, err := m.CheckState(ctx, ys)
		if err != nil {
			return 0, err
		}
		for y, p := range byY {
			if st[y] == "UNSPENT" {
				w.S.Proofs[mintURL] = append(w.S.Proofs[mintURL], p)
				added += p.Amount
			}
		}
	}
	return added, w.Save()
}

// Claim mints every paid npub.cash quote not yet claimed. npub.cash keeps
// claimed quotes in its history, so claims are tracked locally (and a mint
// answering "already issued" also marks it).
func (w *Wallet) Claim(ctx context.Context, npc *NPC) (sats uint64, count int, err error) {
	qs, err := npc.Quotes(ctx, 0)
	if err != nil {
		return 0, 0, err
	}
	var firstErr error
	for _, q := range qs {
		key := strings.TrimRight(q.MintURL, "/") + "|" + q.QuoteID
		w.mu.Lock()
		_, done := w.S.Claimed[key]
		w.mu.Unlock()
		if done || q.State == "ISSUED" {
			continue
		}
		if q.State != "PAID" {
			continue
		}
		got, err := w.MintPaidQuote(ctx, strings.TrimRight(q.MintURL, "/"), q.QuoteID, q.Amount, q.Locked)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("claim %s: %w", q.QuoteID, err)
			}
			continue
		}
		if got > 0 {
			sats += got
			count++
		}
	}
	return sats, count, firstErr
}
