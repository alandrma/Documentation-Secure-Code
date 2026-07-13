package jsoninjection

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// --- Mass assignment ---------------------------------------------------

func TestUnmarshalUserInsecure_MassAssignmentIsExploitable(t *testing.T) {
	// Payload attacker untuk endpoint yang kelihatannya "cuma registrasi user biasa".
	payload := []byte(`{"username":"attacker","email":"a@example.com","is_admin":true}`)
	u, err := UnmarshalUserInsecure(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !u.IsAdmin {
		t.Fatalf("expected demonstration to show privilege escalation succeeding, IsAdmin was false")
	}
	// Test ini SENGAJA "hijau" untuk mendokumentasikan bahwa pola binding
	// langsung ke domain struct adalah TRUE POSITIVE ketika ditemukan di
	// handler yang menerima request body dari luar.
}

func TestDecodeUserInputSafe_MassAssignmentBlocked(t *testing.T) {
	payload := strings.NewReader(`{"username":"attacker","email":"a@example.com","password":"x","is_admin":true}`)
	if _, err := DecodeUserInputSafe(payload); err == nil {
		t.Fatalf("expected error: unknown field is_admin should be rejected")
	}
}

func TestDecodeUserInputSafe_HappyPath(t *testing.T) {
	payload := strings.NewReader(`{"username":"alan_red","email":"alan@example.com","password":"S3cur3P@ss"}`)
	u, err := DecodeUserInputSafe(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.IsAdmin {
		t.Fatalf("IsAdmin must never be settable from input")
	}
	if u.Username != "alan_red" {
		t.Fatalf("unexpected username: %s", u.Username)
	}
}

// --- Resource exhaustion / DoS -----------------------------------------

func TestDecodeUserInputSafe_RejectsOversizedPayload(t *testing.T) {
	big := strings.Repeat("a", MaxJSONBodyBytes+10)
	payload := strings.NewReader(`{"username":"` + big + `","email":"a@example.com","password":"x"}`)
	if _, err := DecodeUserInputSafe(payload); err == nil {
		t.Fatalf("expected error for oversized payload")
	}
}

func TestDecodeUserInputSafe_RejectsDeepNesting(t *testing.T) {
	depth := MaxJSONDepth + 10
	nested := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	payload := strings.NewReader(`{"username":"a","email":"a@example.com","password":"x","bomb":` + nested + `}`)
	if _, err := DecodeUserInputSafe(payload); err == nil {
		t.Fatalf("expected error for excessively nested json")
	}
}

// --- Sanitization of decoded values -------------------------------------

func TestDecodeUserInputSafe_RejectsControlCharsAndPathTraversal(t *testing.T) {
	payload := strings.NewReader(`{"username":"alan\u0000../../etc/passwd","email":"a@example.com","password":"x"}`)
	if _, err := DecodeUserInputSafe(payload); err == nil {
		t.Fatalf("expected error: NUL byte + path traversal sequence must fail identifier validation")
	}
}

func TestDecodeUserInputSafe_RejectsInvalidEmail(t *testing.T) {
	payload := strings.NewReader(`{"username":"alan","email":"not-an-email","password":"x"}`)
	if _, err := DecodeUserInputSafe(payload); err == nil {
		t.Fatalf("expected error for invalid email format")
	}
}

// --- Duplicate keys ------------------------------------------------------

func TestDuplicateKeys_LastValueWins(t *testing.T) {
	// Mendokumentasikan behavior encoding/json: kalau object JSON punya key
	// duplikat, nilai TERAKHIR yang menang. Kalau ada komponen upstream
	// (WAF/proxy/API gateway) yang hanya menginspeksi occurrence PERTAMA,
	// perbedaan interpretasi ini adalah validation-bypass / smuggling
	// primitive yang nyata, bukan cuma isu teoretis.
	var u User
	if err := json.Unmarshal([]byte(`{"username":"safe_value","username":"' OR 1=1 --"}`), &u); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Username != "' OR 1=1 --" {
		t.Fatalf("expected last duplicate key to win, got: %q", u.Username)
	}
}

// --- Numeric precision ----------------------------------------------------

func TestUnmarshalToInterface_LosesIntegerPrecision(t *testing.T) {
	// 2^53 + 1: nilai integer di atas ini tidak bisa direpresentasikan
	// secara eksak sebagai float64.
	data := []byte(`{"id": 9007199254740993}`)

	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id, ok := generic["id"].(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", generic["id"])
	}
	if int64(id) == 9007199254740993 {
		t.Fatalf("expected float64 precision loss to reproduce here, but exact value survived")
	}

	// Mitigasi: pakai UseNumber() supaya angka besar tetap presisi
	// (disimpan sebagai json.Number, backed oleh string).
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var precise map[string]interface{}
	if err := dec.Decode(&precise); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	num, ok := precise["id"].(json.Number)
	if !ok {
		t.Fatalf("expected json.Number, got %T", precise["id"])
	}
	if num.String() != "9007199254740993" {
		t.Fatalf("expected exact precision to be preserved, got %s", num.String())
	}
}
