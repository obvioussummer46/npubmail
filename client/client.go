// SPDX-License-Identifier: MIT

// Package client is the Go client for an npubmail server. Its only credential is
// a Nostr secret key; every request carries a NIP-98 signature.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/obvioussummer46/npubmail/internal/auth"
	"github.com/obvioussummer46/npubmail/internal/seal"
)

type Client struct {
	Base string // e.g. https://npubmail.com
	sk   string // hex
	HTTP *http.Client
}

// New builds a client from a hex or nsec secret key.
func New(base, key string) (*Client, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "nsec1") {
		_, v, err := nip19.Decode(key)
		if err != nil {
			return nil, fmt.Errorf("bad nsec: %w", err)
		}
		key = v.(string)
	}
	if _, err := nostr.GetPublicKey(key); err != nil {
		return nil, fmt.Errorf("bad secret key: %w", err)
	}
	return &Client{Base: strings.TrimRight(base, "/"), sk: key, HTTP: &http.Client{Timeout: 150 * time.Second}}, nil
}

// DefaultKeyFile is ~/.config/npubmail/nsec.
func DefaultKeyFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "npubmail", "nsec")
}

// LoadKey reads NPUBMAIL_NSEC, else the key file. With create=true a missing key
// file is generated (mode 600): that is the whole signup.
// DefaultURL is the public npubmail server.
const DefaultURL = "https://npubmail.com"

func LoadKey(path string, create bool) (key string, created bool, err error) {
	if k := strings.TrimSpace(os.Getenv("NPUBMAIL_NSEC")); k != "" {
		return k, false, nil
	}
	if path == "" {
		path = DefaultKeyFile()
	}
	b, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(b)), false, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return "", false, fmt.Errorf("no key: set NPUBMAIL_NSEC or write an nsec to %s (npubmail keygen > %s)", path, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	nsec, _ := nip19.EncodePrivateKey(nostr.GeneratePrivateKey())
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if _, err := f.WriteString(nsec + "\n"); err != nil {
		return "", false, err
	}
	return nsec, true, nil
}

func (c *Client) Npub() string {
	pk, _ := nostr.GetPublicKey(c.sk)
	n, _ := nip19.EncodePublicKey(pk)
	return n
}

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status int
	Body   []byte
}

func (e *APIError) Error() string {
	var m struct{ Error string }
	if json.Unmarshal(e.Body, &m) == nil && m.Error != "" {
		return fmt.Sprintf("npubmail: %d %s", e.Status, m.Error)
	}
	return fmt.Sprintf("npubmail: %d %s", e.Status, strings.TrimSpace(string(e.Body)))
}

func IsStatus(err error, code int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == code
}

// Do sends a signed request and returns the raw body; non-2xx becomes *APIError.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, pow int) ([]byte, error) {
	h, err := auth.Header(ctx, c.sk, method, c.Base+path, body, pow)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", h)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return b, &APIError{res.StatusCode, b}
	}
	return b, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, pow int, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	b, err := c.Do(ctx, method, path, body, pow)
	if err != nil {
		return err
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

type Discovery struct {
	Service    string `json:"service"`
	Domain     string `json:"domain"`
	CreatePoW  int    `json:"create_pow"`
	Receive    bool   `json:"receive"`
	Send       bool   `json:"send"`
	SendPerDay int    `json:"send_per_day"`
	SendPolicy string `json:"send_policy"`
	Encrypted  bool   `json:"encrypted"`
	Retention  int    `json:"retention_days"`
	Payments   *struct {
		Currency string `json:"currency"`
		Method   string `json:"method"`
		Pricing  struct {
			SendNewRecipient int64            `json:"send_new_recipient"`
			StoragePerMonth  map[string]int64 `json:"storage_per_month"`
		} `json:"pricing"`
	} `json:"payments,omitempty"`
	Docs string `json:"docs"`
}

func (c *Client) Discovery(ctx context.Context) (*Discovery, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.Base+"/.well-known/npubmail", nil)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var d Discovery
	return &d, json.NewDecoder(res.Body).Decode(&d)
}

type Mailbox struct {
	Npub          string    `json:"npub"`
	Addresses     []string  `json:"addresses"`
	CreatedAt     time.Time `json:"created_at"`
	RetentionDays int       `json:"retention_days"`
	Lightning     *struct {
		ForwardsTo string   `json:"forwards_to"`
		Addresses  []string `json:"addresses"`
	} `json:"lightning,omitempty"`
}

// SetLightning makes the mailbox's addresses work as Lightning addresses that
// forward to addr (any existing Lightning address; "" turns it off).
func (c *Client) SetLightning(ctx context.Context, addr string) (*Mailbox, error) {
	var m Mailbox
	return &m, c.doJSON(ctx, "PUT", "/v1/lightning", map[string]string{"address": addr}, 0, &m)
}

func (c *Client) Mailbox(ctx context.Context) (*Mailbox, error) {
	var m Mailbox
	return &m, c.doJSON(ctx, "GET", "/v1/mailbox", nil, 0, &m)
}

// CreateMailbox mines the server's proof of work and registers the key.
// Idempotent: an existing mailbox is returned as is.
func (c *Client) CreateMailbox(ctx context.Context, name string) (*Mailbox, error) {
	d, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	var m Mailbox
	return &m, c.doJSON(ctx, "POST", "/v1/mailbox", map[string]string{"name": name}, d.CreatePoW, &m)
}

// EnsureMailbox returns the mailbox, creating it on first use.
func (c *Client) EnsureMailbox(ctx context.Context, name string) (*Mailbox, bool, error) {
	m, err := c.Mailbox(ctx)
	if err == nil {
		return m, false, nil
	}
	if !IsStatus(err, 404) {
		return nil, false, err
	}
	m, err = c.CreateMailbox(ctx, name)
	if IsStatus(err, 409) && name != "" { // name taken: fall back to the npub address
		m, err = c.CreateMailbox(ctx, "")
	}
	return m, err == nil, err
}

type Alias struct {
	Address   string     `json:"address"`
	Label     string     `json:"label"`
	AllowFrom string     `json:"allow_from"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func (c *Client) CreateAlias(ctx context.Context, ttlHours int, allowFrom, label string) (*Alias, error) {
	var a Alias
	return &a, c.doJSON(ctx, "POST", "/v1/aliases", map[string]any{"ttl_hours": ttlHours, "allow_from": allowFrom, "label": label}, 0, &a)
}

func (c *Client) Aliases(ctx context.Context) ([]Alias, error) {
	var r struct{ Aliases []Alias }
	return r.Aliases, c.doJSON(ctx, "GET", "/v1/aliases", nil, 0, &r)
}

type Auth struct {
	SPF     string   `json:"spf"`
	DKIM    []string `json:"dkim"`
	Aligned bool     `json:"aligned"`
}

type Link struct {
	URL    string `json:"url"`
	Action bool   `json:"action"` // looks like verify/confirm/reset/login
}

type Message struct {
	ID         string    `json:"id"`
	To         string    `json:"to"`
	MailFrom   string    `json:"mail_from"`
	From       string    `json:"from"`
	Subject    string    `json:"subject"`
	Date       string    `json:"date,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Auth       Auth      `json:"auth"`
	Codes      []string  `json:"codes"`
	Links      []Link    `json:"links,omitempty"`
	Warnings   []string  `json:"warnings"`
	Text       string    `json:"text,omitempty"`
	HTML       string    `json:"html,omitempty"`
	Size       int       `json:"size"`
	Sealed     string    `json:"sealed,omitempty"`
	SealedBody string    `json:"sealed_body,omitempty"`
}

// unseal decrypts a message stored encrypted to our key, in place.
func (c *Client) unseal(m *Message) error {
	if m.Sealed != "" {
		b, err := seal.Open(c.sk, m.Sealed)
		if err != nil {
			return fmt.Errorf("decrypt message %s: %w", m.ID, err)
		}
		var h struct {
			To, MailFrom, From, Subject, Date string
			Auth                              Auth
			Codes, Warnings                   []string
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(b, &raw)
		_ = json.Unmarshal(b, &h)
		var mf string
		_ = json.Unmarshal(raw["mail_from"], &mf)
		m.To, m.MailFrom, m.From, m.Subject, m.Date = h.To, mf, h.From, h.Subject, h.Date
		m.Auth, m.Codes, m.Warnings = h.Auth, h.Codes, h.Warnings
		m.Sealed = ""
	}
	if m.SealedBody != "" {
		b, err := seal.Open(c.sk, m.SealedBody)
		if err != nil {
			return fmt.Errorf("decrypt message %s: %w", m.ID, err)
		}
		var body struct {
			Text  string `json:"text"`
			HTML  string `json:"html"`
			Links []Link `json:"links"`
		}
		_ = json.Unmarshal(b, &body)
		m.Text, m.HTML, m.Links = body.Text, body.HTML, body.Links
		m.SealedBody = ""
	}
	if m.Codes == nil {
		m.Codes = []string{}
	}
	if m.Warnings == nil {
		m.Warnings = []string{}
	}
	return nil
}

// Messages lists newest first. after: only newer than that id. wait: long-poll seconds (max 120).
func (c *Client) Messages(ctx context.Context, after string, limit, wait int) ([]Message, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
	}
	if wait > 0 {
		q.Set("wait", fmt.Sprint(wait))
	}
	var r struct{ Messages []Message }
	if err := c.doJSON(ctx, "GET", "/v1/messages?"+q.Encode(), nil, 0, &r); err != nil {
		return nil, err
	}
	for i := range r.Messages {
		if err := c.unseal(&r.Messages[i]); err != nil {
			return nil, err
		}
	}
	return r.Messages, nil
}

func (c *Client) Message(ctx context.Context, id string, html bool) (*Message, error) {
	p := "/v1/messages/" + url.PathEscape(id)
	if html {
		p += "?html=1"
	}
	var m Message
	if err := c.doJSON(ctx, "GET", p, nil, 0, &m); err != nil {
		return nil, err
	}
	return &m, c.unseal(&m)
}

func (c *Client) DeleteMessage(ctx context.Context, id string) error {
	return c.doJSON(ctx, "DELETE", "/v1/messages/"+url.PathEscape(id), nil, 0, nil)
}

// Beginning is the cursor for "everything", returned by Cursor for an empty
// inbox so that a message arriving right after is not skipped.
const Beginning = "beginning"

// Cursor returns a position to wait from: the newest message id, or
// Beginning for an empty inbox.
func (c *Client) Cursor(ctx context.Context) (string, error) {
	ms, err := c.Messages(ctx, "", 1, 0)
	if err != nil {
		return "", err
	}
	if len(ms) == 0 {
		return Beginning, nil
	}
	return ms[0].ID, nil
}

// Filter narrows WaitFor. Empty fields match anything; matching is
// case-insensitive substring.
type Filter struct {
	From     string // matched against From header and envelope sender
	To       string // e.g. an alias address
	Subject  string
	WantCode bool // only messages with an extracted code
}

func (f Filter) match(m Message) bool {
	has := func(hay, needle string) bool {
		return needle == "" || strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
	}
	return has(m.From+" "+m.MailFrom, f.From) && has(m.To, f.To) && has(m.Subject, f.Subject) &&
		(!f.WantCode || len(m.Codes) > 0)
}

var ErrTimeout = errors.New("timed out waiting for mail")

// WaitFor blocks until a message newer than `after` matches the filter.
// after == "" means "newer than whatever is newest right now"; Beginning
// means "any message".
func (c *Client) WaitFor(ctx context.Context, after string, f Filter, timeout time.Duration) (*Message, error) {
	if after == "" {
		var err error
		if after, err = c.Cursor(ctx); err != nil {
			return nil, err
		}
	}
	if after == Beginning {
		after = ""
	}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, ErrTimeout
		}
		w := int(left.Seconds())
		if w > 110 {
			w = 110
		}
		if w < 1 {
			w = 1
		}
		ms, err := c.Messages(ctx, after, 0, w)
		if err != nil {
			return nil, err
		}
		if len(ms) == 0 {
			continue
		}
		for i := len(ms) - 1; i >= 0; i-- { // oldest new message first
			if f.match(ms[i]) {
				return c.Message(ctx, ms[i].ID, false)
			}
		}
		after = ms[0].ID
	}
}

type SendRequest struct {
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Text      string   `json:"text"`
	FromName  string   `json:"from_name,omitempty"`
	ReplyTo   string   `json:"reply_to,omitempty"`
	InReplyTo string   `json:"in_reply_to,omitempty"`
	PaymentID string   `json:"payment_id,omitempty"`
}

type SendResult struct {
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	Results   []struct {
		To        string `json:"to"`
		OK        bool   `json:"ok"`
		MX        string `json:"mx,omitempty"`
		Detail    string `json:"detail"`
		TLS       bool   `json:"tls"`
		Temporary bool   `json:"temporary,omitempty"`
		Queued    bool   `json:"queued,omitempty"`
	} `json:"results"`
	PaidSats  int64  `json:"paid_sats,omitempty"`
	PaymentID string `json:"payment_id,omitempty"`
}

type OutboxItem struct {
	ID            string    `json:"id"`
	MessageID     string    `json:"message_id"`
	To            string    `json:"to"`
	Subject       string    `json:"subject"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastError     string    `json:"last_error"`
	QueuedAt      time.Time `json:"queued_at"`
}

type Outbox struct {
	Pending     []OutboxItem `json:"pending"`
	Bounces24h  int          `json:"bounces_24h"`
	BounceLimit int          `json:"bounce_limit"`
}

func (c *Client) Outbox(ctx context.Context) (*Outbox, error) {
	var o Outbox
	return &o, c.doJSON(ctx, "GET", "/v1/outbox", nil, 0, &o)
}

func (c *Client) Send(ctx context.Context, r SendRequest) (*SendResult, error) {
	var out SendResult
	b, err := c.Do(ctx, "POST", "/v1/send", mustJSON(r), 0)
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out)
	}
	if err != nil && IsStatus(err, 502) && out.MessageID != "" { // every recipient refused: still a result
		return &out, err
	}
	return &out, err
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// ---- payments (pay per action, no balances)

// PaymentRequired is returned (as *APIError with Status 402) when an action
// costs sats. Pay Bolt11, then repeat the request with PaymentID.
type PaymentRequired struct {
	PriceSats int64    `json:"price_sats"`
	Bolt11    string   `json:"bolt11"`
	PaymentID string   `json:"payment_id"`
	Mint      string   `json:"invoice_mint,omitempty"`
	Needing   []string `json:"recipients_needing_payment,omitempty"`
}

// AsPaymentRequired extracts the invoice from a 402 error.
func AsPaymentRequired(err error) (*PaymentRequired, bool) {
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 402 {
		return nil, false
	}
	var p PaymentRequired
	if json.Unmarshal(ae.Body, &p) != nil || p.Bolt11 == "" {
		return nil, false
	}
	return &p, true
}

type InvoiceStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pending, paid, used, expired
	Amount int64  `json:"amount_sats"`
}

func (c *Client) InvoiceStatus(ctx context.Context, id string) (*InvoiceStatus, error) {
	var t InvoiceStatus
	return &t, c.doJSON(ctx, "GET", "/v1/invoices/"+url.PathEscape(id), nil, 0, &t)
}

type Storage struct {
	RetentionDays  int              `json:"retention_days"`
	DefaultDays    int              `json:"default_days"`
	RetentionUntil *time.Time       `json:"retention_until,omitempty"`
	Tiers          map[string]int64 `json:"tiers_sats_per_30_days,omitempty"`
}

func (c *Client) Storage(ctx context.Context) (*Storage, error) {
	var r Storage
	return &r, c.doJSON(ctx, "GET", "/v1/storage", nil, 0, &r)
}

type StorageResult struct {
	RetentionDays  int       `json:"retention_days"`
	RetentionUntil time.Time `json:"retention_until"`
	PaidSats       int64     `json:"paid_sats"`
	PaymentID      string    `json:"payment_id"`
}

// BuyStorage returns a 402 *APIError with an invoice until it is paid.
func (c *Client) BuyStorage(ctx context.Context, days, months int, paymentID string) (*StorageResult, error) {
	var r StorageResult
	return &r, c.doJSON(ctx, "POST", "/v1/storage", map[string]any{"days": days, "months": months, "payment_id": paymentID}, 0, &r)
}
