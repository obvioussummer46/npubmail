// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/obvioussummer46/npubmail/client/cashu"
)

// The built-in wallet is optional. It exists for agents that have no
// Lightning wallet: every npub already has <npub>@npub.cash as a Lightning
// address; payments to it wait at a Cashu mint (default Minibits) as quotes
// locked to the agent's key, and this wallet claims and spends them. The
// wallet seed is derived from the same Nostr key as the mailbox. Agents with
// their own wallet never need any of this.

const (
	DefaultMint     = "https://mint.minibits.cash/Bitcoin"
	DefaultNpubCash = "https://npub.cash"
)

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func WalletFile() string { return envOr("NPUBMAIL_WALLET_FILE", cashu.DefaultPath()) }
func WalletMint() string { return strings.TrimRight(envOr("NPUBMAIL_MINT", DefaultMint), "/") }
func NpubCashURL() string {
	return strings.TrimRight(envOr("NPUBMAIL_NPUBCASH_URL", DefaultNpubCash), "/")
}

func (c *Client) skBytes() []byte { b, _ := hex.DecodeString(c.sk); return b }

// SecretKey returns the 32-byte secret key (for local wallet use only).
func (c *Client) SecretKey() []byte { return c.skBytes() }

// NPC is the npub.cash client for this key.
func (c *Client) NPC() *cashu.NPC { return cashu.NewNPC(NpubCashURL(), c.sk) }

// NpubCashAddress is <npub>@<npub.cash host>: this key's Lightning address.
func (c *Client) NpubCashAddress() string {
	u, err := url.Parse(NpubCashURL())
	host := "npub.cash"
	if err == nil && u.Host != "" {
		host = u.Host
	}
	return c.Npub() + "@" + host
}

// OpenWallet opens the wallet file; cashu.ErrNoWallet if not set up.
func (c *Client) OpenWallet() (*cashu.Wallet, error) { return cashu.Open(WalletFile(), c.skBytes()) }

// WalletSetup is the result of setting up the optional built-in wallet.
type WalletSetup struct {
	LightningAddress string   `json:"lightning_address"`
	Mint             string   `json:"mint"`
	Locked           bool     `json:"payments_locked_to_your_key"`
	WalletFile       string   `json:"wallet_file"`
	Forwarding       []string `json:"also_receives_at,omitempty"`
	Limits           cashu.Limits
	Note             string `json:"note"`
}

// SetupWallet creates the wallet file, points npub.cash at the mint with
// quote locking on, and (if forward and none is set yet) makes the mailbox
// addresses forward to the npub.cash address.
func (c *Client) SetupWallet(ctx context.Context, forward bool) (*WalletSetup, error) {
	mint := WalletMint()
	w, err := cashu.Create(WalletFile(), c.skBytes(), mint)
	if err != nil {
		return nil, err
	}
	npc := c.NPC()
	if err := npc.SetMint(ctx, mint); err != nil {
		return nil, fmt.Errorf("npub.cash: set mint: %w", err)
	}
	locked := true
	if err := npc.SetLock(ctx, true); err != nil {
		return nil, fmt.Errorf("npub.cash: lock payments to your key: %w (refusing to continue unlocked)", err)
	}
	u, err := npc.User(ctx)
	if err == nil && (!u.LockQuote || strings.TrimRight(u.MintURL, "/") != mint) {
		return nil, fmt.Errorf("npub.cash did not apply settings (mint %s, locked %v)", u.MintURL, u.LockQuote)
	}
	res := &WalletSetup{LightningAddress: c.NpubCashAddress(), Mint: mint, Locked: locked, WalletFile: w.Path, Limits: w.S.Limits,
		Note: "Optional convenience wallet. Anyone can pay your Lightning address; run wallet balance to collect. Back up your key file: it restores both mailbox and wallet. The mint is custodial and in beta: keep small amounts only."}
	if forward {
		if mb, err := c.Mailbox(ctx); err == nil {
			if mb.Lightning == nil {
				if mb2, err := c.SetLightning(ctx, res.LightningAddress); err == nil && mb2.Lightning != nil {
					res.Forwarding = mb2.Lightning.Addresses
				}
			} else {
				res.Forwarding = mb.Lightning.Addresses
			}
		}
	}
	return res, nil
}

// WalletStatus is balance after collecting incoming payments.
type WalletStatus struct {
	Balance          uint64       `json:"balance_sats"`
	Collected        uint64       `json:"collected_now_sats"`
	LightningAddress string       `json:"lightning_address"`
	Limits           cashu.Limits `json:"limits"`
	Warning          string       `json:"warning,omitempty"`
}

// WalletBalance settles pending payments, claims incoming ones and reports.
func (c *Client) WalletBalance(ctx context.Context) (*WalletStatus, error) {
	w, err := c.OpenWallet()
	if err != nil {
		return nil, err
	}
	st := &WalletStatus{LightningAddress: c.NpubCashAddress(), Limits: w.S.Limits}
	_ = w.Settle(ctx)
	got, _, err := w.Claim(ctx, c.NPC())
	if err != nil {
		st.Warning = "could not collect all incoming payments: " + err.Error()
	}
	st.Collected = got
	st.Balance = w.Balance()
	return st, nil
}

// PayInvoice pays a bolt11 from the built-in wallet (within limits).
func (c *Client) PayInvoice(ctx context.Context, bolt11 string) (*cashu.PayResult, error) {
	w, err := c.OpenWallet()
	if err != nil {
		return nil, err
	}
	if w.Balance() == 0 {
		_, _, _ = w.Claim(ctx, c.NPC())
	}
	return w.Pay(ctx, bolt11)
}

// PayExact pays only if the invoice is for exactly sats (guards autopay
// against a 402 whose invoice does not match its stated price).
func (c *Client) PayExact(ctx context.Context, bolt11 string, sats uint64) (*cashu.PayResult, error) {
	w, err := c.OpenWallet()
	if err != nil {
		return nil, err
	}
	if w.Balance() < sats {
		_, _, _ = w.Claim(ctx, c.NPC())
	}
	return w.PayExact(ctx, bolt11, sats)
}

// IsNoWallet reports whether err means the optional wallet is not set up.
func IsNoWallet(err error) bool { return errors.Is(err, cashu.ErrNoWallet) }

// RestoreWallet rebuilds the wallet from the key (creating the file if it was lost).
func (c *Client) RestoreWallet(ctx context.Context) (restored, balance uint64, err error) {
	w, err := c.OpenWallet()
	if IsNoWallet(err) {
		w, err = cashu.Create(WalletFile(), c.skBytes(), WalletMint())
	}
	if err != nil {
		return 0, 0, err
	}
	n, err := w.Restore(ctx, w.S.Mint)
	if err != nil {
		return 0, w.Balance(), err
	}
	// claim anything still waiting at npub.cash too
	_, _, _ = w.Claim(ctx, c.NPC())
	return n, w.Balance(), nil
}
