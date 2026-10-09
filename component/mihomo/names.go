/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package mihomo

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxNodeNameLength = 64
	maxIdentifier     = 64
)

var (
	nodeIdentifier  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	groupIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// emojiWords maps common list-decoration emoji to short ASCII words. Other
// emoji are dropped.
var emojiWords = map[rune]string{
	0x26FD: "Fuel", 0x2764: "Heart", 0x2665: "Heart", 0x1F495: "Heart", 0x1F496: "Heart",
	0x1F497: "Heart", 0x1F498: "Heart", 0x1F499: "Heart", 0x1F49A: "Heart", 0x1F49B: "Heart",
	0x1F49C: "Heart", 0x1F49D: "Heart", 0x1F5A4: "Heart", 0x1F90D: "Heart", 0x1F90E: "Heart",
	0x1F9E1: "Heart", 0x1F34E: "Apple", 0x1F352: "Cherry", 0x1F37F: "Popcorn", 0x1F3AE: "Game",
	0x1F3AF: "Target", 0x1F3B5: "Music", 0x1F3E0: "Home", 0x1F42D: "Mouse", 0x1F45B: "Wallet",
	0x1F4A4: "Zzz", 0x1F4DA: "Book", 0x1F4FA: "TV", 0x1FAD2: "Olive", 0x1F680: "Rocket",
	0x1F525: "Fire", 0x2B50: "Star", 0x1F31F: "Star", 0x26A1: "Bolt", 0x1F310: "Global",
	0x1F512: "Lock", 0x2708: "Plane", 0x1F6EB: "Plane", 0x1F4A1: "Idea", 0x1F3AC: "Movie",
	0x1F4F1: "Phone", 0x1F4BB: "PC", 0x2601: "Cloud", 0x1F6E1: "Shield",
}

// SafeNodeName turns a Mihomo proxy name into a dae node tag. Names that are
// already valid tags are kept verbatim; hyphens are allowed.
func SafeNodeName(name string) string {
	if len(name) <= maxNodeNameLength && nodeIdentifier.MatchString(name) {
		return name
	}
	return sanitizeName(name, true)
}

// SafeGroupName turns a Mihomo group name into a dae group identifier.
func SafeGroupName(name string) string {
	if groupIdentifier.MatchString(name) {
		return name
	}
	return sanitizeName(name, false)
}

func hashedName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", sum[:6])
}

func sanitizeName(name string, allowHyphen bool) string {
	if !utf8.ValidString(name) {
		return hashedName(name)
	}
	var parts []string
	var word strings.Builder
	flush := func() {
		if token := strings.Trim(word.String(), "-_"); token != "" {
			parts = append(parts, token)
		}
		word.Reset()
	}
	token := func(t string) {
		flush()
		parts = append(parts, t)
	}

	runes := []rune(name)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case isInvisible(r):
			continue
		case i+1 < len(runes) && isRegional(r) && isRegional(runes[i+1]):
			token(string([]byte{regionalLetter(r), regionalLetter(runes[i+1])}))
			i++
			continue
		case i+1 < len(runes) && (r == '-' || r == '=') && runes[i+1] == '>':
			flush()
			i++
			continue
		}
		if emoji, ok := emojiWords[r]; ok {
			token(emoji)
			continue
		}
		if r <= 127 && (r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || allowHyphen && r == '-') {
			word.WriteByte(byte(r))
			continue
		}
		// Everything else (separators, punctuation, unmapped emoji, non-ASCII
		// letters) only ends the current word.
		if r == '-' || isSeparator(r) {
			flush()
		}
	}
	flush()

	out := strings.Join(parts, "_")
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	out = strings.Trim(out, "_")
	if out == "" {
		return hashedName(name)
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "n_" + out
	}
	if out == "direct" || out == "block" {
		return hashedName(name)
	}
	if len(out) > maxIdentifier {
		sum := sha256.Sum256([]byte(name))
		suffix := fmt.Sprintf("%x", sum[:3])
		keep := maxIdentifier - 1 - len(suffix)
		out = strings.Trim(out[:keep], "_") + "_" + suffix
	}
	pattern := groupIdentifier
	if allowHyphen {
		pattern = nodeIdentifier
	}
	if !pattern.MatchString(out) {
		return hashedName(name)
	}
	return out
}

func isRegional(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

func regionalLetter(r rune) byte { return byte('A' + (r - 0x1F1E6)) }

func isInvisible(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFE0E, 0xFE0F, 0x20E3:
		return true
	}
	return false
}

func isSeparator(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '|', '/', '\\', '.', ',', ':', ';', '\'', '"', '`',
		'(', ')', '[', ']', '{', '}', '<', '>',
		'+', '=', '*', '?', '&', '%', '#', '@', '!', '~',
		0x00B7, 0x2013, 0x2014, 0x2022, 0x30FB, 0x2192, 0x21D2:
		return true
	}
	return false
}
