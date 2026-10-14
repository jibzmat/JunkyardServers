package token

import (
	"errors"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	tok, rec, err := New("10.0.0.1:7443", "abcd", true, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(tok.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != tok {
		t.Fatalf("got %+v want %+v", got, tok)
	}
	if rec.SecretHash == tok.Secret {
		t.Fatal("record stores the plain secret")
	}
	if !rec.Trusted {
		t.Fatal("trusted flag lost")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "jy1.", "jy1.!!!", "xx.e30", "jy1.e30"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded", s)
		}
	}
}

func TestCheck(t *testing.T) {
	tok, rec, _ := New("a:1", "f", false, time.Hour, 1)
	now := time.Now()
	if err := rec.Check("wrong", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := rec.Check(tok.Secret, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if err := rec.Check(tok.Secret, now); err != nil {
		t.Fatalf("valid: %v", err)
	}
	rec.Uses = 1
	if err := rec.Check(tok.Secret, now); !errors.Is(err, ErrExhausted) {
		t.Fatalf("exhausted: %v", err)
	}
}
