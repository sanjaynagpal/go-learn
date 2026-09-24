# Bash: `inspect-jwt.sh`

A shell script that decodes a JWT and prints its header, payload, a claim summary,
readable times and an expiry status. **It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Linux, macOS, WSL, and Git Bash on Windows |
| **Needs** | bash, `base64`, `date` (all standard). **jq is optional but recommended.** |

## Setup

```bash
chmod +x jwt/bash/inspect-jwt.sh

# Optional: put it on your PATH
ln -s "$PWD/jwt/bash/inspect-jwt.sh" ~/.local/bin/inspect-jwt
```

Install jq for pretty-printed JSON and the full claim summary:

| Platform | Command |
|----------|---------|
| Debian / Ubuntu | `sudo apt install jq` |
| Fedora / RHEL | `sudo dnf install jq` |
| macOS | `brew install jq` |
| Windows (for Git Bash) | `winget install jqlang.jq` |

Without jq the script still works, but the JSON is printed on one line and
array-valued claims (such as `aud: ["api","web"]` or `roles`) are left out of the
summary. It prints a hint when that happens.

## Usage

```
inspect-jwt.sh [--raw] [--no-color] [TOKEN]

  -r, --raw       print only the decoded header and payload JSON
      --no-color  disable coloured output (also honoured: NO_COLOR env var)
  -h, --help      show this help
```

The token is read from the arguments, then from piped stdin, then from the clipboard.

```bash
./inspect-jwt.sh eyJhbGciOi...
./inspect-jwt.sh "Authorization: Bearer eyJhbGciOi..."
./inspect-jwt.sh < ../samples/expired.jwt
curl -s https://login.example.com/token ... | jq -r .access_token | ./inspect-jwt.sh
./inspect-jwt.sh --raw "$TOKEN" | jq -s '.[1].scope'  # --raw prints header then payload
./inspect-jwt.sh                                       # reads the clipboard
```

Clipboard sources, tried in order: `pbpaste` (macOS), `wl-paste` (Wayland),
`xclip`, `xsel` (X11), `/dev/clipboard` (Git Bash / Cygwin), `powershell.exe` (WSL).

## Sample output

```
$ ./inspect-jwt.sh < ../samples/expired.jwt

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
  "aud": "api",
  "iat": 1700000000,
  "exp": 1700003600,
  "client_id": "cli-app"
}

=== SUMMARY ===
Issuer:            https://login.example.com
Subject:           user42
Audience:          api
Client ID:         cli-app
Issued at:         2023-11-14 22:13:20 UTC  (2023-11-14 17:13:20 local)
Expires:           2023-11-14 23:13:20 UTC  (2023-11-14 18:13:20 local)
Lifetime:          01:00:00

STATUS: EXPIRED (1044d 12:22:47 ago)

=== SIGNATURE ===
Algorithm:         HS256
Key ID (kid):      demo-hs256
Signature length:  43 chars (Base64Url)
Signature NOT verified by this script.
```

## Portability notes

The script handles these platform differences for you:

- **`base64 -d` vs `-D`:** GNU coreutils, BusyBox and macOS 13+ use `-d`. Older
  macOS uses `-D`. The script tries both.
- **`date`:** GNU date formats a timestamp with `-d @SECONDS`, BSD/macOS date
  with `-r SECONDS`. The script detects which one it has.
- **Padding:** `base64` needs `=` padding, which JWTs leave out. The script adds it.
- **`alg: none` tokens** end with an empty signature (`header.payload.`). Bash's
  `read -a` drops that trailing empty field, so the script adds it back.

## Related

- [`../jq/`](../jq/): a pure-jq filter that outputs a JSON report instead of text.
- [`../openssl/`](../openssl/): verify the signature from Bash.
