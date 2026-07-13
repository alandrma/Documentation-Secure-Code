package jsoninjection

import (
	"strings"
	"testing"
)

func TestMarshalUser_ExcludesPassword(t *testing.T) {
	u := User{ID: 1, Username: "alan", Email: "alan@example.com", Password: "supersecret", IsAdmin: false}
	out, err := MarshalUser(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "supersecret") {
		t.Fatalf("password value leaked in serialized output: %s", out)
	}
	if strings.Contains(string(out), "Password") {
		t.Fatalf("password field name leaked in serialized output: %s", out)
	}
}

func TestMarshalUser_HTMLEscapingByDefault(t *testing.T) {
	u := User{Username: `<script>alert(1)</script>`}
	out, err := MarshalUser(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "<script>") {
		t.Fatalf("expected HTML characters to be escaped by default, got: %s", out)
	}
	if !strings.Contains(string(out), `\u003cscript\u003e`) {
		t.Fatalf("expected \\u003cscript\\u003e escaping, got: %s", out)
	}
}

func TestMarshalUserRaw_DisablesEscaping(t *testing.T) {
	u := User{Username: `<b>bold</b>`}
	out, err := MarshalUserRaw(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "<b>bold</b>") {
		t.Fatalf("expected raw HTML to survive when escaping is disabled, got: %s", out)
	}
}
