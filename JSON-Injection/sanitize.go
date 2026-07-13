package jsoninjection

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
)

// sanitizeIdentifier menghapus control character (termasuk embedded NUL,
// CR, LF) lalu menegakkan whitelist charset yang konservatif.
//
// Kenapa ini penting terlepas dari fakta bahwa encoding/json sendiri sudah
// "aman" secara memory-safety: field string hasil Unmarshal adalah RAW
// bytes dari attacker. Kalau string itu nanti dipakai sebagai:
//   - komponen path file       -> path traversal / NUL byte truncation
//   - baris log                -> log injection / log forging (CRLF)
//   - argumen ke exec.Command  -> tergantung sink, tetap perlu validasi
//
// maka JSON decoding BUKAN sanitization boundary-nya. Ini yang jadi dasar
// verdict "FP jika hanya unmarshal, TP jika hasil unmarshal langsung
// dipakai ke sink sensitif tanpa sanitasi di antaranya" untuk banyak
// finding Fortify "Path Manipulation" / "Log Forging" yang sumbernya
// ditandai sebagai JSON deserialization.
func sanitizeIdentifier(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty value")
	}

	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	cleaned := b.String()

	for _, r := range cleaned {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid character %q in identifier", r)
		}
	}
	return cleaned, nil
}

// sanitizeEmail memvalidasi format lewat net/mail (RFC 5322 parser di
// stdlib) alih-alih regex custom yang gampang salah/bisa di-bypass.
func sanitizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid email: %w", err)
	}
	return addr.Address, nil
}
