# npubmail clients

**Email for AI agents, owned by a Nostr key.** No signup, no password, no API key: the agent's keypair is the account.

This repository holds the open clients for the hosted service at **[npubmail.com](https://npubmail.com)**:

- `cmd/npubmail`: command-line client
- `cmd/npubmail-mcp`: MCP server (Claude Code, Hermes, OpenClaw, any MCP client)
- `client/`: Go library (`EnsureMailbox`, `CreateAlias`, `WaitFor`, `Send`, ...)
- `skills/npubmail/SKILL.md`: agent skill
- `docs/`: HTTP API, the sealed-mail format (`SEAL.md`) with test vectors, and Python/JS examples

## Install

```sh
curl -fsSL https://npubmail.com/install | sh       # prebuilt, checksummed binaries
# or from source:
go install github.com/obvioussummer46/npubmail/cmd/npubmail-mcp@latest
go install github.com/obvioussummer46/npubmail/cmd/npubmail@latest
```

MCP config:

```yaml
mcp_servers:
  npubmail:
    command: npubmail-mcp          # talks to https://npubmail.com
    timeout: 660                   # wait_for_* can block up to 600 s
```

## Use it

```sh
npubmail init myagent                      # -> myagent@npubmail.com (key at ~/.config/npubmail/nsec)
npubmail alias --from github.com --ttl 24  # disposable, sender-locked address
npubmail code --timeout 120                # block until mail arrives, print the OTP
```

Agents: start at https://npubmail.com/llms.txt.

## What the service does

- **Receive:** free. Disposable aliases per signup, codes and links extracted.
- **Encrypted at rest:** each message is sealed to the owner's Nostr key (see `docs/SEAL.md`); the server cannot read stored mail.
- **Send:** replies to people who wrote to you are free, and so is mail to other npubmail mailboxes. Mailing a new recipient costs a few sats over Lightning, per message, with no account balance.
- **Inbound TLS** (STARTTLS), DKIM/SPF/DMARC on outbound.

## Your key is your account

`~/.config/npubmail/nsec` is the only credential. Back it up; there is no reset. The clients sign every request locally (NIP-98) and never send the key anywhere.

## Licence

MIT (`LICENSE`): clients, library, protocol packages, skill and examples. The server is not in this repository.
