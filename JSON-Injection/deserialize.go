package jsoninjection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxJSONBodyBytes membatasi ukuran body sebelum di-decode. Tanpa ini,
	// json.Unmarshal/Decoder akan mengalokasikan memori sebesar payload yang
	// dikirim attacker -> resource-exhaustion DoS. Sesuaikan per endpoint.
	MaxJSONBodyBytes = 1 << 20 // 1 MiB

	// MaxJSONDepth membatasi kedalaman nesting object/array. encoding/json
	// stdlib TIDAK punya limit depth bawaan (berbeda dari beberapa parser
	// XML/YAML), sehingga payload dengan nesting sangat dalam bisa memicu
	// stack growth / CPU time yang signifikan saat parsing. Verifikasi angka
	// pastinya untuk versi Go yang dipakai di production sebelum dianggap
	// sebagai batas hard limit yang aman.
	MaxJSONDepth = 20
)

// UnmarshalUserInsecure meniru pola yang paling sering muncul sebagai
// finding "JSON Injection" / "Mass Assignment" di Fortify scan pada
// codebase Go: binding bytes yang tidak dipercaya langsung ke domain
// struct yang punya privileged field.
//
// JANGAN dipakai di production. Fungsi ini sengaja dipertahankan supaya
// TestUnmarshalUserInsecure_MassAssignmentIsExploitable bisa
// mendemonstrasikan bahwa pola ini adalah TRUE POSITIVE ketika ditemukan
// menempel langsung ke HTTP handler (bukan default Fortify FP).
func UnmarshalUserInsecure(data []byte) (User, error) {
	var u User
	err := json.Unmarshal(data, &u)
	return u, err
}

// DecodeUserInputSafe adalah pola yang hardened:
//  1. size-limited read       -> mitigasi resource-exhaustion DoS
//  2. depth check sebelum decode -> mitigasi deeply-nested payload DoS
//  3. decode ke DTO sempit (UserRegistrationInput), BUKAN ke domain struct
//     -> mass assignment mustahil secara struktural, bukan cuma tervalidasi
//  4. DisallowUnknownFields   -> field asing (mis. "is_admin") ditolak,
//     bukan cuma di-diamkan diam-diam
//  5. dec.More() check        -> menolak trailing JSON/data setelah value
//     pertama (mitigasi request smuggling via multiple JSON documents)
//  6. sanitasi & validasi eksplisit sebelum dipetakan ke domain struct
func DecodeUserInputSafe(r io.Reader) (User, error) {
	limited := io.LimitReader(r, MaxJSONBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return User{}, fmt.Errorf("read body: %w", err)
	}
	if len(raw) > MaxJSONBodyBytes {
		return User{}, errors.New("request body exceeds maximum allowed size")
	}

	if depth := maxJSONDepth(raw); depth > MaxJSONDepth {
		return User{}, fmt.Errorf("json nesting depth %d exceeds limit %d", depth, MaxJSONDepth)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var in UserRegistrationInput
	if err := dec.Decode(&in); err != nil {
		return User{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return User{}, errors.New("trailing data after JSON value")
	}

	username, err := sanitizeIdentifier(in.Username)
	if err != nil {
		return User{}, fmt.Errorf("username: %w", err)
	}
	email, err := sanitizeEmail(in.Email)
	if err != nil {
		return User{}, fmt.Errorf("email: %w", err)
	}
	if in.Password == "" {
		return User{}, errors.New("password: empty value")
	}

	return User{
		Username: username,
		Email:    email,
		Password: in.Password, // hashing (bcrypt/argon2) terjadi di layer lain, di luar scope contoh ini
		IsAdmin:  false,       // privileged field TIDAK PERNAH diturunkan dari input user
	}, nil
}

// maxJSONDepth menghitung kedalaman nesting maksimum lewat token stream,
// tanpa perlu materialize seluruh struktur jadi Go value dulu.
func maxJSONDepth(data []byte) int {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth, max := 0, 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > max {
					max = depth
				}
			case '}', ']':
				depth--
			}
		}
	}
	return max
}
