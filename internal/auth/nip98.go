// SPDX-License-Identifier: MIT

// Package auth implements npubmail's only credential: a Nostr key.
//
// Every API request carries a NIP-98 HTTP-auth event (kind 27235) signed by the
// mailbox owner's key. There is no account, password or API key to issue, leak
// or rotate. Creating a mailbox additionally requires NIP-13 proof of work on
// that event, so mass-creating mailboxes costs CPU instead of a captcha.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
)

const KindHTTPAuth = 27235

var ErrNoAuth = errors.New("missing Authorization: Nostr <base64 event>")

// Verifier checks NIP-98 headers. BaseURL is the public origin the client
// signed against (e.g. https://mail.example.org), so it works behind a proxy.
type Verifier struct {
	BaseURL string
	MaxSkew time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

func NewVerifier(baseURL string) *Verifier {
	return &Verifier{BaseURL: strings.TrimRight(baseURL, "/"), MaxSkew: 60 * time.Second, seen: map[string]time.Time{}}
}

// Verify returns the signed event (whose PubKey is the caller's identity).
func (v *Verifier) Verify(r *http.Request, body []byte) (*nostr.Event, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Nostr ") {
		return nil, ErrNoAuth
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len("Nostr "):]))
	if err != nil {
		return nil, fmt.Errorf("auth header is not base64: %w", err)
	}
	var evt nostr.Event
	if err := json.Unmarshal(raw, &evt); err != nil {
		return nil, fmt.Errorf("auth event is not JSON: %w", err)
	}
	if evt.Kind != KindHTTPAuth {
		return nil, fmt.Errorf("auth event kind %d, want %d", evt.Kind, KindHTTPAuth)
	}
	if !evt.CheckID() {
		return nil, errors.New("auth event id does not match its content")
	}
	if ok, err := evt.CheckSignature(); err != nil || !ok {
		return nil, errors.New("auth event signature is invalid")
	}
	skew := time.Since(evt.CreatedAt.Time())
	if skew < -v.MaxSkew || skew > v.MaxSkew {
		return nil, errors.New("auth event is too old or from the future")
	}
	if u := evt.Tags.Find("u"); u == nil || u[1] != v.BaseURL+r.URL.RequestURI() {
		return nil, fmt.Errorf("auth event u tag must be %s", v.BaseURL+r.URL.RequestURI())
	}
	if m := evt.Tags.Find("method"); m == nil || !strings.EqualFold(m[1], r.Method) {
		return nil, errors.New("auth event method tag does not match")
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		if p := evt.Tags.Find("payload"); p == nil || p[1] != hex.EncodeToString(sum[:]) {
			return nil, errors.New("auth event payload tag does not match the body")
		}
	}
	if !v.firstSeen(evt.ID) {
		return nil, errors.New("auth event already used")
	}
	return &evt, nil
}

// Work is the proof of work the caller committed to on this event.
func Work(evt *nostr.Event) int { return nip13.CommittedDifficulty(evt) }

func (v *Verifier) firstSeen(id string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	for k, t := range v.seen {
		if now.Sub(t) > 2*v.MaxSkew {
			delete(v.seen, k)
		}
	}
	if _, dup := v.seen[id]; dup {
		return false
	}
	v.seen[id] = now
	return true
}

// Header builds the Authorization header value for a request. pow > 0 mines
// a NIP-13 nonce first (needed for mailbox creation).
func Header(ctx context.Context, sk, method, url string, body []byte, pow int) (string, error) {
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return "", err
	}
	evt := nostr.Event{
		Kind:      KindHTTPAuth,
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"u", url}, {"method", strings.ToUpper(method)}},
	}
	// Random tag so two identical requests in the same second still get
	// distinct event ids (the server rejects a reused id as a replay).
	var n [8]byte
	_, _ = rand.Read(n[:])
	evt.Tags = append(evt.Tags, nostr.Tag{"n", hex.EncodeToString(n[:])})
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		evt.Tags = append(evt.Tags, nostr.Tag{"payload", hex.EncodeToString(sum[:])})
	}
	if pow > 0 {
		tag, err := nip13.DoWork(ctx, evt, pow)
		if err != nil {
			return "", err
		}
		evt.Tags = append(evt.Tags, tag)
	}
	if err := evt.Sign(sk); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(evt)
	return "Nostr " + base64.StdEncoding.EncodeToString(raw), nil
}
