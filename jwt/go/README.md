# Go: `inspect-jwt`

A compiled command-line tool that decodes a JWT and prints its header, payload, a
claim summary, readable times and an expiry status. It uses only the Go standard
library. **It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Windows, Linux, macOS (amd64 and arm64) |
| **Needs** | Go 1.25+ to build. The resulting binary needs nothing. |

## Build and install

```bash
cd jwt/go

# Build for the current machine
go build -o inspect-jwt .          # Linux / macOS
go build -o inspect-jwt.exe .      # Windows

# Or install into $GOPATH/bin (usually ~/go/bin, which should be on your PATH)
go install .
```

### Build for other platforms

Go can build for any platform from any machine:

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/inspect-jwt-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -o dist/inspect-jwt-linux-arm64 .
GOOS=darwin  GOARCH=arm64 go build -o dist/inspect-jwt-macos-arm64 .
GOOS=windows GOARCH=amd64 go build -o dist/inspect-jwt-windows-amd64.exe .
```

In PowerShell, set the variables first: `$env:GOOS='linux'; $env:GOARCH='amd64'; go build -o dist/inspect-jwt-linux-amd64 .`

## Usage

```
inspect-jwt [--raw] [--no-color] [TOKEN]

  -r, --raw       print only the decoded header and payload JSON
      --no-color  disable coloured output (also honoured: NO_COLOR env var)
  -h, --help      show this help
```

The token is read from the command-line arguments, then from piped stdin, then
from the clipboard.

```bash
inspect-jwt eyJhbGciOi...
inspect-jwt "Authorization: Bearer eyJhbGciOi..."
inspect-jwt Bearer eyJhbGciOi...           # arguments are joined, so quotes are optional
cat token.txt | inspect-jwt
inspect-jwt < ../samples/expired.jwt
inspect-jwt --raw "$TOKEN" > decoded.json
inspect-jwt                                 # reads the clipboard
```

PowerShell:

```powershell
.\inspect-jwt.exe $token
Get-Content token.txt | .\inspect-jwt.exe
```

The clipboard is read with `Get-Clipboard` on Windows, `pbpaste` on macOS, and
`wl-paste`, `xclip` or `xsel` on Linux (or `powershell.exe` under WSL).

## Sample output

```
$ inspect-jwt < ../samples/valid.jwt

=== HEADER ===
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "demo-hs256"
}

=== PAYLOAD ===
{
  "iss": "https://login.example.com",
  "sub": "user42",
  ...
}

=== SUMMARY ===
Issuer:            https://login.example.com
Subject:           user42
Audience:          api, web
Token ID:          9f1c2e7a-demo
Scope:             read write
Roles:             reader, writer
Name:              Jane Doe
Email:             jane@example.com
Issued at:         2026-09-24 11:01:49 UTC  (2026-09-24 07:01:49 local)
Not before:        2026-09-24 11:01:49 UTC  (2026-09-24 07:01:49 local)
Expires:           2100-01-01 00:00:00 UTC  (2099-12-31 19:00:00 local)
Lifetime:          26761d 12:58:11

STATUS: VALID (expires in 26761d 12:25:05)

=== SIGNATURE ===
Algorithm:         HS256
Key ID (kid):      demo-hs256
Signature length:  43 chars (Base64Url)
Signature NOT verified by this tool.
```

Exit code is `0` on success and `1` if the token can't be read or decoded.

## Tests

```bash
go test ./...
```

The tests run the tool against the tokens in [`../samples/`](../samples/) with a
fixed clock, and cover prefix stripping, padding, malformed input and duration
formatting.

## How it works

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Argument handling, token input, decoding and output |
| [`vt_windows.go`](vt_windows.go) | Turns on ANSI colour support in older Windows consoles |
| [`vt_other.go`](vt_other.go) | Does nothing on other platforms |
| [`main_test.go`](main_test.go) | Tests |

Key points:

- `base64.RawURLEncoding` decodes Base64Url without padding, which is exactly
  what JWT uses (any `=` padding is trimmed first).
- `json.Indent` pretty-prints the JSON **without reordering keys** or changing
  number precision. Decoding into a struct and re-encoding would do both.
- Claims are decoded into `map[string]json.RawMessage` so each value can be shown
  in the way that suits its type.

## Going further: verifying the signature

This tool only decodes. To verify tokens in Go code, use a library:

- [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt): parse and
  validate with a key, checking `exp`, `nbf`, `iss` and `aud`.
- [`github.com/lestrrat-go/jwx/v3`](https://github.com/lestrrat-go/jwx): full
  JOSE support, including fetching and caching JWKS key sets.

```go
tok, err := jwt.Parse(raw, keyFunc,
    jwt.WithValidMethods([]string{"RS256"}),
    jwt.WithIssuer("https://login.example.com"),
    jwt.WithAudience("api"),
    jwt.WithLeeway(2*time.Minute))
```

To check a signature from the command line, see [`../openssl/`](../openssl/).
