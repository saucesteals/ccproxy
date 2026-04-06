// Package cch computes Claude Code fingerprint and attestation values.
package cch

import (
	"crypto/sha256"
	"fmt"

	"github.com/cespare/xxhash/v2"
)

const (
	// Salt is the hardcoded salt from backend validation. Must match exactly.
	Salt = "59cf53e54c78"

	// Seed is the xxhash64 seed for attestation computation.
	Seed = uint64(0x6E52736AC806831E)

	// Mask is the bitmask applied to the xxhash64 output.
	Mask = uint64(0xFFFFF)

	// Placeholder is the zero-value CCH attestation placeholder embedded in billing headers.
	Placeholder = "cch=00000"
)

// Positions are the character indices extracted from the first user message.
var Positions = [3]int{4, 7, 20}

// Fingerprint computes the 3-char CCH fingerprint from the first user message.
// Algorithm: SHA256(salt + msg[4] + msg[7] + msg[20] + version)[:3].
func Fingerprint(firstUserMsg, version string) string {
	var chars [3]byte
	for i, pos := range Positions {
		if pos < len(firstUserMsg) {
			chars[i] = firstUserMsg[pos]
		} else {
			chars[i] = '0'
		}
	}
	input := fmt.Sprintf("%s%c%c%c%s", Salt, chars[0], chars[1], chars[2], version)
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum[:])[:3]
}

// Attestation computes the 5-char CCH attestation over the serialized body.
// Algorithm: xxhash64(body, seed) & 0xFFFFF, zero-padded hex.
func Attestation(body []byte) string {
	d := xxhash.NewWithSeed(Seed)
	d.Write(body)
	return fmt.Sprintf("%05x", d.Sum64()&Mask)
}
