// Command inspect-jwt decodes and displays the contents of a JWT (JSON Web Token).
//
// It splits the token into header, payload and signature, Base64Url-decodes the
// header and payload, pretty-prints them as JSON, and interprets the common time
// claims (exp, iat, nbf, auth_time) as readable UTC/local dates with an expiry
// status.
//
// It does NOT verify the signature. Do not trust the output for security decisions.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const usage = `Usage: inspect-jwt [--raw] [--no-color] [TOKEN]

Decodes a JWT and prints its header, payload, a claim summary and expiry status.
The signature is NOT verified.

The token is read from, in order:
  1. the command-line arguments ("Bearer " / "Authorization: Bearer " is stripped)
  2. standard input, when it is piped
  3. the clipboard

Options:
  -r, --raw       print only the decoded header and payload JSON
      --no-color  disable coloured output (also honoured: NO_COLOR env var)
  -h, --help      show this help
`

type options struct {
	raw   bool
	color bool
	now   time.Time
}

func main() {
	opt := options{color: isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == "", now: time.Now()}

	var tokenArgs []string
	for _, a := range os.Args[1:] {
		switch a {
		case "-r", "--raw", "-raw":
			opt.raw = true
		case "--no-color", "-no-color":
			opt.color = false
		case "-h", "--help", "-help":
			fmt.Print(usage)
			return
		default:
			tokenArgs = append(tokenArgs, a)
		}
	}
	if opt.color {
		enableVirtualTerminal()
	}

	token, err := readToken(tokenArgs)
	if err != nil {
		fail(err)
	}
	if err := inspect(os.Stdout, token, opt); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// --- Getting the token -------------------------------------------------------

func readToken(args []string) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	if !isTerminal(os.Stdin) {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		if len(bytes.TrimSpace(b)) > 0 {
			return string(b), nil
		}
	}
	t, err := readClipboard()
	if err != nil || strings.TrimSpace(t) == "" {
		return "", errors.New("no token supplied. Pass it as an argument, pipe it in, or copy it to the clipboard")
	}
	fmt.Fprintln(os.Stderr, "(Token read from clipboard)")
	return t, nil
}

// readClipboard shells out to the platform's clipboard tool.
func readClipboard() (string, error) {
	var candidates [][]string
	switch runtime.GOOS {
	case "windows":
		candidates = [][]string{{"powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"}}
	case "darwin":
		candidates = [][]string{{"pbpaste"}}
	default:
		candidates = [][]string{
			{"wl-paste", "--no-newline"},
			{"xclip", "-o", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--output"},
			{"powershell.exe", "-NoProfile", "-Command", "Get-Clipboard -Raw"}, // WSL
		}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		out, err := exec.Command(c[0], c[1:]...).Output()
		if err == nil {
			return string(out), nil
		}
	}
	return "", errors.New("no clipboard tool available")
}

var bearerPrefix = regexp.MustCompile(`(?i)^(authorization:\s*)?bearer\s+`)
var whitespace = regexp.MustCompile(`\s+`)

// cleanToken strips an optional "Bearer " / "Authorization: Bearer " prefix,
// surrounding quotes and any whitespace (e.g. line breaks from copy/paste).
func cleanToken(t string) string {
	t = bearerPrefix.ReplaceAllString(strings.TrimSpace(t), "")
	t = strings.Trim(strings.TrimSpace(t), `"'`)
	return whitespace.ReplaceAllString(t, "")
}

// --- Decoding ---------------------------------------------------------------

// decodeSegment decodes one Base64Url segment, with or without '=' padding.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func prettyJSON(b []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return string(b)
	}
	return out.String()
}

func inspect(w io.Writer, rawToken string, opt options) error {
	c := colors(opt.color)
	token := cleanToken(rawToken)
	parts := strings.Split(token, ".")

	switch len(parts) {
	case 3:
	case 5:
		fmt.Fprintln(w, c.yellow("WARNING: Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded."))
	default:
		return fmt.Errorf("invalid JWT: expected 3 dot-separated parts, found %d", len(parts))
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("header is not a JSON object: %w", err)
	}

	var payloadJSON []byte
	var payload map[string]json.RawMessage
	if len(parts) == 3 {
		if payloadJSON, err = decodeSegment(parts[1]); err != nil {
			return fmt.Errorf("could not decode payload: %w", err)
		}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			return fmt.Errorf("payload is not a JSON object: %w", err)
		}
	}

	if opt.raw {
		fmt.Fprintln(w, prettyJSON(headerJSON))
		if payloadJSON != nil {
			fmt.Fprintln(w, prettyJSON(payloadJSON))
		}
		return nil
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.cyan("=== HEADER ==="))
	fmt.Fprintln(w, prettyJSON(headerJSON))

	if payload != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, c.cyan("=== PAYLOAD ==="))
		fmt.Fprintln(w, prettyJSON(payloadJSON))
		fmt.Fprintln(w)
		fmt.Fprintln(w, c.cyan("=== SUMMARY ==="))
		printSummary(w, payload, opt.now, c)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.cyan("=== SIGNATURE ==="))
	alg := display(header["alg"])
	fmt.Fprintf(w, "%-18s %s\n", "Algorithm:", alg)
	if kid, ok := header["kid"]; ok {
		fmt.Fprintf(w, "%-18s %s\n", "Key ID (kid):", display(kid))
	}
	if strings.EqualFold(alg, "none") {
		fmt.Fprintln(w, c.red("WARNING: alg is 'none' - token is unsigned!"))
	}
	fmt.Fprintf(w, "%-18s %d chars (Base64Url)\n", "Signature length:", len(parts[len(parts)-1]))
	fmt.Fprintln(w, c.dim("Signature NOT verified by this tool."))
	fmt.Fprintln(w)
	return nil
}

// --- Summary ----------------------------------------------------------------

var claimLabels = []struct{ key, label string }{
	{"iss", "Issuer"}, {"sub", "Subject"}, {"aud", "Audience"}, {"azp", "Authorized party"},
	{"jti", "Token ID"}, {"scope", "Scope"}, {"scp", "Scopes"}, {"roles", "Roles"},
	{"name", "Name"}, {"email", "Email"}, {"upn", "UPN"}, {"preferred_username", "Username"},
	{"tid", "Tenant ID"}, {"oid", "Object ID"}, {"client_id", "Client ID"}, {"appid", "App ID"},
}

var timeLabels = []struct{ key, label string }{
	{"iat", "Issued at"}, {"nbf", "Not before"}, {"exp", "Expires"}, {"auth_time", "Auth time"},
}

func printSummary(w io.Writer, payload map[string]json.RawMessage, now time.Time, c palette) {
	for _, l := range claimLabels {
		if v, ok := payload[l.key]; ok {
			fmt.Fprintf(w, "%-18s %s\n", l.label+":", display(v))
		}
	}

	times := map[string]time.Time{}
	for _, l := range timeLabels {
		v, ok := payload[l.key]
		if !ok {
			continue
		}
		t, err := unixTime(v)
		if err != nil {
			fmt.Fprintf(w, "%-18s %s (unparseable)\n", l.label+":", display(v))
			continue
		}
		times[l.key] = t
		fmt.Fprintf(w, "%-18s %s UTC  (%s local)\n", l.label+":",
			t.UTC().Format(time.DateTime), t.Local().Format(time.DateTime))
	}

	iat, hasIat := times["iat"]
	exp, hasExp := times["exp"]
	nbf, hasNbf := times["nbf"]
	if hasIat && hasExp {
		fmt.Fprintf(w, "%-18s %s\n", "Lifetime:", formatDuration(exp.Sub(iat)))
	}

	fmt.Fprintln(w)
	switch {
	case hasNbf && nbf.After(now):
		fmt.Fprintln(w, c.yellow("STATUS: NOT YET VALID (valid in "+formatDuration(nbf.Sub(now))+")"))
	case hasExp && !exp.After(now):
		fmt.Fprintln(w, c.red("STATUS: EXPIRED ("+formatDuration(now.Sub(exp))+" ago)"))
	case hasExp:
		fmt.Fprintln(w, c.green("STATUS: VALID (expires in "+formatDuration(exp.Sub(now))+")"))
	default:
		fmt.Fprintln(w, c.yellow("STATUS: No 'exp' claim - token does not expire."))
	}
}

// display renders a claim value: strings unquoted, arrays joined with ", ",
// anything else as compact JSON.
func display(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	var arr []json.RawMessage
	if json.Unmarshal(v, &arr) == nil {
		items := make([]string, len(arr))
		for i, e := range arr {
			items[i] = display(e)
		}
		return strings.Join(items, ", ")
	}
	var out bytes.Buffer
	if json.Compact(&out, v) == nil {
		return out.String()
	}
	return string(v)
}

// unixTime parses a NumericDate claim (seconds since the epoch, possibly fractional).
func unixTime(v json.RawMessage) (time.Time, error) {
	var n json.Number
	if err := json.Unmarshal(v, &n); err != nil {
		return time.Time{}, err
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(f), 0), nil
}

// formatDuration renders a duration as "[Nd ]HH:MM:SS" (sign dropped).
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	s := int64(d / time.Second)
	days, s := s/86400, s%86400
	hms := fmt.Sprintf("%02d:%02d:%02d", s/3600, s%3600/60, s%60)
	if days > 0 {
		return fmt.Sprintf("%dd %s", days, hms)
	}
	return hms
}

// --- Terminal colours -------------------------------------------------------

type palette bool

func colors(on bool) palette { return palette(on) }

func (p palette) wrap(code, s string) string {
	if !p {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p palette) cyan(s string) string   { return p.wrap("36", s) }
func (p palette) green(s string) string  { return p.wrap("32", s) }
func (p palette) yellow(s string) string { return p.wrap("33", s) }
func (p palette) red(s string) string    { return p.wrap("31", s) }
func (p palette) dim(s string) string    { return p.wrap("90", s) }

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
