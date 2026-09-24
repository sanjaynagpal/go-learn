package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// now is fixed so the STATUS lines are deterministic.
var now = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func sample(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "samples", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func run(t *testing.T, token string, raw bool) string {
	t.Helper()
	var sb strings.Builder
	if err := inspect(&sb, token, options{raw: raw, now: now}); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return sb.String()
}

func TestSamples(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{"valid.jwt", []string{
			"Issuer:            https://login.example.com",
			"Audience:          api, web",
			"Roles:             reader, writer",
			"Expires:           2100-01-01 00:00:00 UTC",
			"STATUS: VALID (expires in 26761d 12:00:00)",
			"Key ID (kid):      demo-hs256",
		}},
		{"expired.jwt", []string{
			"Client ID:         cli-app",
			"Lifetime:          01:00:00",
			"STATUS: EXPIRED (",
		}},
		{"not-yet-valid.jwt", []string{"STATUS: NOT YET VALID (valid in "}},
		{"alg-none.jwt", []string{
			"STATUS: No 'exp' claim",
			"WARNING: alg is 'none'",
			"Signature length:  0 chars",
		}},
		{"encrypted-jwe.jwt", []string{"looks like an encrypted JWE", "Algorithm:         RSA-OAEP"}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			out := run(t, sample(t, tt.file), false)
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q\n%s", w, out)
				}
			}
		})
	}
}

func TestJWEHasNoPayloadSection(t *testing.T) {
	if out := run(t, sample(t, "encrypted-jwe.jwt"), false); strings.Contains(out, "PAYLOAD") {
		t.Errorf("JWE output should not contain a payload section:\n%s", out)
	}
}

func TestRaw(t *testing.T) {
	out := run(t, sample(t, "valid.jwt"), true)
	if strings.Contains(out, "===") || !strings.Contains(out, `"alg": "HS256"`) || !strings.Contains(out, `"sub": "user42"`) {
		t.Errorf("unexpected raw output:\n%s", out)
	}
}

func TestCleanToken(t *testing.T) {
	for in, want := range map[string]string{
		"abc.def.ghi":                          "abc.def.ghi",
		"  Bearer abc.def.ghi\n":               "abc.def.ghi",
		"Authorization: bearer abc.def.ghi":    "abc.def.ghi",
		`"abc.def.ghi"`:                        "abc.def.ghi",
		"abc.de\r\nf.ghi":                      "abc.def.ghi",
		"AUTHORIZATION:Bearer   'abc.def.ghi'": "abc.def.ghi",
	} {
		if got := cleanToken(in); got != want {
			t.Errorf("cleanToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeSegmentAcceptsPadding(t *testing.T) {
	for _, s := range []string{"eyJhIjoxfQ", "eyJhIjoxfQ=="} {
		b, err := decodeSegment(s)
		if err != nil || string(b) != `{"a":1}` {
			t.Errorf("decodeSegment(%q) = %q, %v", s, b, err)
		}
	}
}

func TestErrors(t *testing.T) {
	for _, tok := range []string{"", "abc", "a.b", "a.b.c.d", "!!!.e30.x", "e30.!!!.x", "WzFd.e30.x"} {
		if err := inspect(&strings.Builder{}, tok, options{now: now}); err == nil {
			t.Errorf("inspect(%q) succeeded, want error", tok)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                            "00:00:00",
		59*time.Minute + time.Second: "00:59:01",
		-time.Hour:                   "01:00:00",
		26*time.Hour + 5*time.Second: "1d 02:00:05",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
