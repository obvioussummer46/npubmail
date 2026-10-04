// SPDX-License-Identifier: MIT

package cashu

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// NPC talks to an npub.cash server: every npub gets <npub>@npub.cash as a
// Lightning address; payments become mint quotes the owner claims here.
type NPC struct {
	URL  string // https://npub.cash
	SK   string // nostr secret key hex
	HTTP *http.Client
}

func NewNPC(url, skHex string) *NPC {
	return &NPC{URL: strings.TrimRight(url, "/"), SK: skHex, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type NPCUser struct {
	Pubkey    string `json:"pubkey"`
	MintURL   string `json:"mintUrl"`
	LockQuote bool   `json:"lockQuote"`
	Name      string `json:"name,omitempty"`
}

type NPCQuote struct {
	MintURL string `json:"mintUrl"`
	QuoteID string `json:"quoteId"`
	Amount  uint64 `json:"amount"`
	State   string `json:"state"`
	Locked  bool   `json:"locked"`
	PaidAt  int64  `json:"paidAt"`
}

// auth signs NIP-98 over origin+path (npub.cash ignores the query string).
func (n *NPC) auth(method, path string, body []byte) (string, error) {
	pk, err := nostr.GetPublicKey(n.SK)
	if err != nil {
		return "", err
	}
	var r [8]byte
	_, _ = rand.Read(r[:])
	ev := nostr.Event{Kind: 27235, PubKey: pk, CreatedAt: nostr.Now(),
		Tags: nostr.Tags{{"u", n.URL + path}, {"method", method}, {"n", hex.EncodeToString(r[:])}}}
	if len(body) > 0 {
		h := sha256.Sum256(body)
		ev.Tags = append(ev.Tags, nostr.Tag{"payload", hex.EncodeToString(h[:])})
	}
	if err := ev.Sign(n.SK); err != nil {
		return "", err
	}
	b, _ := json.Marshal(ev)
	return "Nostr " + base64.StdEncoding.EncodeToString(b), nil
}

func (n *NPC) do(ctx context.Context, method, path, query string, in any, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	h, err := n.auth(method, path, body)
	if err != nil {
		return err
	}
	u := n.URL + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", h)
	req.Header.Set("User-Agent", "npubmail-wallet")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := n.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var env struct {
		Error   bool            `json:"error"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(b, &env)
	if res.StatusCode >= 300 || env.Error {
		msg := env.Message
		if msg == "" {
			msg = strings.TrimSpace(string(b))
		}
		return fmt.Errorf("npub.cash %s %s: %d %s", method, path, res.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

func (n *NPC) User(ctx context.Context) (*NPCUser, error) {
	var r struct{ User NPCUser }
	return &r.User, n.do(ctx, "GET", "/api/v2/user/info", "", nil, &r)
}

func (n *NPC) SetMint(ctx context.Context, mint string) error {
	return n.do(ctx, "PATCH", "/api/v2/user/mint", "", map[string]string{"mint_url": mint}, nil)
}

func (n *NPC) SetLock(ctx context.Context, lock bool) error {
	return n.do(ctx, "PATCH", "/api/v2/user/lock", "", map[string]bool{"lockQuotes": lock}, nil)
}

// Quotes returns all paid quotes (paginated; history includes already-claimed ones).
func (n *NPC) Quotes(ctx context.Context, since int64) ([]NPCQuote, error) {
	var all []NPCQuote
	for off := 0; ; off += 50 {
		var r struct {
			Quotes []NPCQuote `json:"quotes"`
		}
		q := "limit=50&offset=" + strconv.Itoa(off)
		if since > 0 {
			q += "&since=" + strconv.FormatInt(since, 10)
		}
		if err := n.do(ctx, "GET", "/api/v2/wallet/quotes", q, nil, &r); err != nil {
			return nil, err
		}
		all = append(all, r.Quotes...)
		if len(r.Quotes) < 50 {
			return all, nil
		}
	}
}
