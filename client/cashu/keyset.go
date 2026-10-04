// SPDX-License-Identifier: MIT

package cashu

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

// VerifyKeysetID checks that a mint's published keys hash to the keyset id
// (NUT-02, version 01). This stops a mint from silently swapping the keys
// behind an id the wallet already trusts.
func VerifyKeysetID(k *KeysetKeys, inputFeePPK uint64) error {
	if !strings.HasPrefix(k.ID, "01") {
		return nil // legacy 00 ids use a truncated hash; not used for new outputs
	}
	got := KeysetIDv2(k.Keys, k.Unit, inputFeePPK, k.FinalExpiry)
	if got != k.ID {
		return fmt.Errorf("cashu: keyset id %s does not match its keys (%s)", k.ID, got)
	}
	return nil
}

func KeysetIDv2(keys map[string]string, unit string, inputFeePPK uint64, finalExpiry *int64) string {
	type kv struct {
		amt uint64
		pk  string
	}
	var list []kv
	for a, pk := range keys {
		n, _ := strconv.ParseUint(a, 10, 64)
		list = append(list, kv{n, strings.ToLower(pk)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].amt < list[j].amt })
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = strconv.FormatUint(e.amt, 10) + ":" + e.pk
	}
	pre := strings.Join(parts, ",") + "|unit:" + strings.ToLower(unit)
	if inputFeePPK != 0 {
		pre += "|input_fee_ppk:" + strconv.FormatUint(inputFeePPK, 10)
	}
	if finalExpiry != nil && *finalExpiry != 0 {
		pre += "|final_expiry:" + strconv.FormatInt(*finalExpiry, 10)
	}
	h := sha256.Sum256([]byte(pre))
	return "01" + hex.EncodeToString(h[:])
}

func parsePub(h string) (*btcec.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(b)
}

// Y is hex(hash_to_curve(secret)), the proof's id for NUT-07 state checks.
func Y(secret string) (string, error) {
	p, err := HashToCurve([]byte(secret))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(p.SerializeCompressed()), nil
}
