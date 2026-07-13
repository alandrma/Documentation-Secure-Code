package jsoninjection

import (
	"bytes"
	"encoding/json"
	"io"
)

// MarshalUser men-serialize User untuk response API publik.
//
// Security note: json.Marshal (dan json.Encoder tanpa SetEscapeHTML(false))
// secara default meng-escape karakter <, >, dan & menjadi \u003c \u003e \u0026.
// Ini adalah mitigasi bawaan Go terhadap stored-XSS ketika output JSON
// nantinya di-embed langsung ke dalam context HTML/<script> (misalnya lewat
// server-side templating tanpa proper context-aware escaping di lapisan
// template-nya). Jangan dianggap sebagai pengganti context-aware output
// encoding di layer presentasi - ini cuma defense-in-depth tambahan.
func MarshalUser(u User) ([]byte, error) {
	return json.Marshal(u)
}

// MarshalUserRaw menonaktifkan HTML-escaping (SetEscapeHTML(false)).
// HANYA dipakai untuk konteks machine-to-machine yang tidak pernah masuk ke
// HTML/JS context (contoh: payload internal ke message broker, RPC antar
// service). Kalau dipakai untuk endpoint yang responsnya bisa berakhir di
// browser, ini membuka kembali vektor stored-XSS yang tadinya sudah
// dimitigasi oleh default behavior json.Marshal.
func MarshalUserRaw(u User) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(u); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeUser menulis User langsung ke io.Writer (streaming), berguna untuk
// http.ResponseWriter tanpa perlu allocate buffer perantara.
func EncodeUser(w io.Writer, u User) error {
	return json.NewEncoder(w).Encode(u)
}
