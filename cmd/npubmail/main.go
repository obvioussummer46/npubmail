// SPDX-License-Identifier: MIT

// npubmail is the agent-side CLI. Its only credential is a Nostr secret key;
// mail is stored encrypted to that key and decrypted here.
//
//	npubmail keygen                       new key (prints nsec to stdout)
//	npubmail init [name]                  create the mailbox (mines proof of work)
//	npubmail whoami                       addresses of this key
//	npubmail alias [--ttl 24] [--from d] [--label l]   disposable address
//	npubmail aliases                      list aliases
//	npubmail ls [--after id]              list messages
//	npubmail read <id> [--html]           one message, extracted
//	npubmail wait [--timeout 120] [--after id]  block until mail arrives
//	npubmail code [--timeout 120]         wait for the next mail and print its code
//	npubmail send --to a@b.c [--to …] --subject s [--text t | < body] [--name n]
//	npubmail outbox                       pending retries, bounce count
//	npubmail invoice <id>                 status of a payment request
//	npubmail storage [--days 30 --months 1 [--payment-id id]]  show / buy extended storage
//
// Paid actions answer 402 with a Lightning invoice (bolt11, payment_id).
// Pay it, then repeat the same command; there are no balances.
//
//	npubmail rm <id>
//
// Lightning (all optional; any Lightning wallet you already have works):
//
//	npubmail lightning <you@wallet.example>   your mailbox addresses also work as Lightning addresses, forwarding there ("" = off)
//	npubmail wallet setup [--no-forward]      built-in ecash wallet for agents WITHOUT a wallet: <npub>@npub.cash
//	npubmail wallet balance                   collect incoming payments, show balance
//	npubmail wallet pay <bolt11>              pay an invoice (capped by wallet limits)
//	npubmail wallet limits [--per-payment N] [--per-day N]
//	npubmail wallet restore                   rebuild the wallet from your key after losing wallet.json
//
// Config (all optional): NPUBMAIL_URL (server, default https://npubmail.com),
// NPUBMAIL_NSEC or NPUBMAIL_KEY_FILE (secret key; `npubmail init` creates
// ~/.config/npubmail/nsec on first use).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/obvioussummer46/npubmail/client"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "keygen" {
		nsec, _ := nip19.EncodePrivateKey(nostr.GeneratePrivateKey())
		fmt.Println(nsec)
		return
	}
	base := os.Getenv("NPUBMAIL_URL")
	if base == "" {
		base = client.DefaultURL
	}
	// init creates the key on first use; every other command needs it.
	key, created, err := client.LoadKey(os.Getenv("NPUBMAIL_KEY_FILE"), cmd == "init")
	if created {
		fmt.Fprintf(os.Stderr, "new key saved to %s (back it up: it is the account)\n", client.DefaultKeyFile())
	}
	if err != nil {
		die(err)
	}
	c, err := client.New(base, key)
	if err != nil {
		die(err)
	}
	ctx := context.Background()
	switch cmd {
	case "init":
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		fmt.Fprintln(os.Stderr, "mining proof of work...")
		m, err := c.CreateMailbox(ctx, name)
		out(m, err)
	case "whoami":
		m, err := c.Mailbox(ctx)
		out(m, err)
	case "alias":
		fs := flag.NewFlagSet("alias", flag.ExitOnError)
		ttl := fs.Int("ttl", 24, "hours until the address stops accepting mail")
		from := fs.String("from", "", "only accept mail from this sender domain (comma-separated)")
		label := fs.String("label", "", "note to self")
		_ = fs.Parse(args)
		a, err := c.CreateAlias(ctx, *ttl, *from, *label)
		out(a, err)
	case "aliases":
		as, err := c.Aliases(ctx)
		out(map[string]any{"aliases": as}, err)
	case "ls":
		fs := flag.NewFlagSet("ls", flag.ExitOnError)
		after := fs.String("after", "", "only messages newer than this id")
		_ = fs.Parse(args)
		ms, err := c.Messages(ctx, *after, 0, 0)
		out(map[string]any{"messages": ms}, err)
	case "read":
		fs := flag.NewFlagSet("read", flag.ExitOnError)
		html := fs.Bool("html", false, "include the HTML body")
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			usage()
		}
		m, err := c.Message(ctx, fs.Arg(0), *html)
		out(m, err)
	case "wait", "code":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		timeout := fs.Int("timeout", 120, "seconds to wait")
		after := fs.String("after", "", "wait for mail newer than this id (default: newest now)")
		_ = fs.Parse(args)
		m, err := c.WaitFor(ctx, *after, client.Filter{WantCode: cmd == "code"}, time.Duration(*timeout)*time.Second)
		if err != nil {
			die(err)
		}
		if cmd == "code" {
			fmt.Println(m.Codes[0])
			return
		}
		out(m, nil)
	case "send":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		var to multi
		fs.Var(&to, "to", "recipient (repeatable)")
		subject := fs.String("subject", "", "subject")
		text := fs.String("text", "", "body (default: read stdin)")
		name := fs.String("name", "", "display name")
		replyTo := fs.String("reply-to", "", "Reply-To address")
		pid := fs.String("payment-id", "", "invoice id from the 402 response, after paying")
		_ = fs.Parse(args)
		body := *text
		if body == "" {
			b, _ := io.ReadAll(os.Stdin)
			body = string(b)
		}
		r, err := c.Send(ctx, client.SendRequest{To: to, Subject: *subject, Text: body, FromName: *name, ReplyTo: *replyTo, PaymentID: *pid})
		if r != nil && r.MessageID == "" {
			r = nil
		}
		out(r, err)
	case "outbox":
		o, err := c.Outbox(ctx)
		out(o, err)
	case "invoice":
		if len(args) != 1 {
			usage()
		}
		t, err := c.InvoiceStatus(ctx, args[0])
		out(t, err)
	case "storage":
		fs := flag.NewFlagSet("storage", flag.ExitOnError)
		days := fs.Int("days", 0, "buy this retention tier in days (omit to show the current plan)")
		months := fs.Int("months", 1, "how many 30-day periods to buy")
		pid := fs.String("payment-id", "", "invoice id from the 402 response, after paying")
		_ = fs.Parse(args)
		if *days == 0 {
			r, err := c.Storage(ctx)
			out(r, err)
			return
		}
		r, err := c.BuyStorage(ctx, *days, *months, *pid)
		out(r, err)
	case "lightning":
		addr := ""
		if len(args) > 0 {
			addr = args[0]
		}
		m, err := c.SetLightning(ctx, addr)
		out(m, err)
	case "wallet":
		walletCmd(ctx, c, args)
	case "rm":
		if len(args) != 1 {
			usage()
		}
		out(map[string]bool{"ok": true}, c.DeleteMessage(ctx, args[0]))
	default:
		usage()
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// out prints v as JSON (unless err with nothing to show) and exits 1 on err,
// printing the server's error body so scripts can parse it.
func out(v any, err error) {
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) {
			fmt.Println(string(ae.Body))
		}
		die(err)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "npubmail:", err)
	os.Exit(1)
}

func walletCmd(ctx context.Context, c *client.Client, args []string) {
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "setup":
		fs := flag.NewFlagSet("wallet setup", flag.ExitOnError)
		noFwd := fs.Bool("no-forward", false, "do not point your mailbox addresses at this wallet")
		_ = fs.Parse(args[1:])
		r, err := c.SetupWallet(ctx, !*noFwd)
		out(r, err)
	case "balance":
		r, err := c.WalletBalance(ctx)
		out(r, err)
	case "pay":
		if len(args) != 2 {
			usage()
		}
		r, err := c.PayInvoice(ctx, args[1])
		out(r, err)
	case "limits":
		fs := flag.NewFlagSet("wallet limits", flag.ExitOnError)
		pp := fs.Uint64("per-payment", 0, "max sats per payment")
		pd := fs.Uint64("per-day", 0, "max sats per 24 h")
		_ = fs.Parse(args[1:])
		w, err := c.OpenWallet()
		if err != nil {
			die(err)
		}
		if *pp > 0 {
			w.S.Limits.PerPayment = *pp
		}
		if *pd > 0 {
			w.S.Limits.PerDay = *pd
		}
		out(w.S.Limits, w.Save())
	case "restore":
		n, bal, err := c.RestoreWallet(ctx)
		out(map[string]any{"restored_sats": n, "balance_sats": bal}, err)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: npubmail keygen|init [name]|whoami|alias|aliases|ls|read <id>|wait|code|send|outbox|invoice <id>|storage [--days 30 --months 1]|rm <id>|lightning <addr>|wallet setup|balance|pay <bolt11>|limits|restore")
	os.Exit(2)
}
