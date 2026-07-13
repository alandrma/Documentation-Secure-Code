package jsoninjection

// User adalah domain struct internal. Field seperti IsAdmin bersifat
// privileged dan TIDAK BOLEH pernah di-bind langsung dari request body
// yang tidak dipercaya (lihat UnmarshalUserInsecure vs DecodeUserInputSafe
// di deserialize.go untuk contoh TP mass assignment vs mitigasinya).
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`        // never marshaled - sengaja di-exclude dari output JSON
	IsAdmin  bool   `json:"is_admin"` // privileged field - lihat catatan di atas
}

// UserRegistrationInput adalah satu-satunya struct yang boleh dipakai untuk
// binding request body dari klien. Struct ini sengaja TIDAK punya field
// IsAdmin/Role/dsb, sehingga secara struktural attacker tidak bisa
// menyisipkan privileged field lewat payload JSON (defense by construction,
// bukan cuma validasi runtime).
type UserRegistrationInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
