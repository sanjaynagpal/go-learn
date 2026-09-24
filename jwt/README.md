# JWT — What's Inside and How to Examine It

A JSON Web Token (JWT, pronounced "jot") is a compact, URL-safe way to pass a set
of **claims** (statements about a user or client) between two parties. It is most
often seen as an OAuth 2.0 / OpenID Connect access token or ID token, sent in an
HTTP header:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxw...
```

This folder has several tools for decoding and checking a token, one per
sub-folder, so developers on Windows, Linux and macOS can use whichever runtime
they already have. See [section 2](#2-tools-in-this-folder).

> **Important:** a JWT is *encoded*, not *encrypted*. Anyone holding the token can
> read its contents. Never put secrets in a JWT, and treat tokens themselves as
> secrets. Anyone who has a valid token can use it until it expires.

---

## 1. Structure

A signed JWT (technically a JWS) has three parts separated by dots:

```
<header>.<payload>.<signature>
```

Each part is **Base64Url** encoded. Base64Url is ordinary Base64 with `+` replaced
by `-`, `/` by `_`, and the trailing `=` padding removed.

| Part      | Contains                                   | Encoded form of          |
|-----------|--------------------------------------------|--------------------------|
| Header    | How the token is signed                    | JSON object              |
| Payload   | The claims                                 | JSON object              |
| Signature | Proof that header + payload weren't altered | Raw bytes                |

A token with **five** parts is an encrypted JWT (JWE). Only its header can be
read without the decryption key.

### 1.1 Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "abc123"
}
```

| Field | Meaning |
|-------|---------|
| `alg` | Signing algorithm. Common values: `HS256` (HMAC + shared secret), `RS256` / `PS256` (RSA), `ES256` (ECDSA), `EdDSA`. `none` means **unsigned**, so reject it. |
| `typ` | Token type, usually `JWT` (sometimes `at+jwt` for access tokens). |
| `kid` | Key ID. Tells the verifier which public key in the issuer's key set (JWKS) to use. |
| `x5t` / `x5c` | Certificate thumbprint / chain, used by some issuers (e.g. Azure AD). |

### 1.2 Payload (claims)

```json
{
  "iss": "https://login.example.com",
  "sub": "user42",
  "aud": ["api", "web"],
  "iat": 1790247709,
  "nbf": 1790247709,
  "exp": 1790251309,
  "jti": "9f1c2e...",
  "scope": "read write",
  "name": "Jane Doe"
}
```

**Registered claims** (defined in RFC 7519; all optional but widely used):

| Claim | Name        | Meaning |
|-------|-------------|---------|
| `iss` | Issuer      | Who created and signed the token. |
| `sub` | Subject     | Who the token is about (user or client ID). |
| `aud` | Audience    | Who the token is meant for. A string or array. An API should reject tokens not addressed to it. |
| `exp` | Expiration  | Time after which the token must be rejected. |
| `nbf` | Not before  | Time before which the token must be rejected. |
| `iat` | Issued at   | When the token was created. |
| `jti` | JWT ID      | Unique identifier, useful for replay detection and revocation. |

Time claims are **NumericDate** values: seconds since 1970-01-01 00:00:00 UTC
(Unix time). For example, `1790251309` is 2026-09-24 12:01:49 UTC.

**Common additional claims** (from OpenID Connect or specific providers):

| Claim | Meaning |
|-------|---------|
| `scope` / `scp` | Permissions granted (space-separated string or array). |
| `roles` | Application roles assigned to the user. |
| `azp` / `client_id` / `appid` | The client application that requested the token. |
| `name`, `email`, `preferred_username`, `upn` | User identity details. |
| `auth_time` | When the user actually authenticated. |
| `nonce` | Ties an ID token to the login request (replay protection). |
| `tid`, `oid` | Azure AD tenant ID and user object ID. |

### 1.3 Signature

The signature is computed over the exact bytes `base64url(header) + "." + base64url(payload)`:

- **HS256:** `HMAC-SHA256(secret, signingInput)`. Issuer and verifier share the same secret.
- **RS256 / ES256:** signed with the issuer's **private** key and verified with the
  matching **public** key, usually published at the issuer's JWKS endpoint
  (e.g. `https://<issuer>/.well-known/jwks.json`, found via
  `https://<issuer>/.well-known/openid-configuration`).

Changing even one character in the header or payload invalidates the signature.

---

## 2. Tools in this folder

Each sub-folder has its own README with installation, usage and examples.

| Folder | What it is | Windows | Linux / macOS | Needs |
|--------|------------|:-------:|:-------------:|-------|
| [`powershell/`](powershell/) | `Inspect-Jwt.ps1` decoder | ✅ | ✅ with PowerShell 7 | PowerShell 5.1 or 7+ |
| [`go/`](go/) | `inspect-jwt` compiled CLI | ✅ | ✅ | Go to build it, then nothing |
| [`bash/`](bash/) | `inspect-jwt.sh` decoder | Git Bash / WSL | ✅ | bash, base64; jq optional |
| [`python/`](python/) | `inspect_jwt.py` decoder | ✅ | ✅ | Python 3.8+, standard library only |
| [`node/`](node/) | `inspect-jwt.mjs` decoder | ✅ | ✅ | Node.js 16+, no npm packages |
| [`jq/`](jq/) | `jwt.jq` filter that outputs a JSON report | ✅ | ✅ | jq 1.6+ |
| [`openssl/`](openssl/) | `verify-jwt.sh` **signature verifier** | Git Bash / WSL | ✅ | bash, OpenSSL |
| [`cli-tools/`](cli-tools/) | Guide to third-party tools (`jwt-cli`, `step`, web decoders) | ✅ | ✅ | the tool itself |
| [`samples/`](samples/) | Test tokens (valid, expired, not-yet-valid, `alg: none`, JWE) | – | – | – |

### Which one should I use?

- **Just want to read a token:** use whichever runtime you already have. The
  PowerShell, Go, Bash, Python and Node decoders all give the same output
  (header, payload, claim summary, readable times, VALID / EXPIRED / NOT YET VALID
  status, signature details).
- **Want one binary you can hand to anyone:** use the Go CLI. You can build it for
  Windows, Linux and macOS from any machine.
- **Scripting or CI, where you want JSON rather than text:** use `jwt.jq`.
- **Need to know whether a token is genuine:** use `openssl/verify-jwt.sh` or one
  of the tools in `cli-tools/`. **None of the decoders check the signature.**

### What the decoders have in common

All five decoders behave the same way:

- The token can come from an argument, from piped input, or from the clipboard
  when neither is given.
- They strip `Bearer ` / `Authorization: Bearer `, surrounding quotes and any
  whitespace or line breaks picked up when copying the token.
- `-r` / `--raw` (`-Raw` in PowerShell) prints only the decoded header and payload JSON.
- They pull well-known identity claims (`iss`, `sub`, `aud`, `scope`, `roles`,
  `email`, `tid`, `oid`, ...) into a summary.
- They convert `iat`, `nbf`, `exp` and `auth_time` to UTC and local time, and
  show the token lifetime.
- They report **VALID**, **EXPIRED** or **NOT YET VALID** based on the current clock.
- They warn about `alg: none` (unsigned) and 5-part encrypted tokens (JWE).
- Colour is used only when writing to a terminal, and never when `NO_COLOR` is
  set (or `--no-color` is passed).
- They exit with code 1 when the token can't be decoded.

A VALID status only means the token hasn't expired. It says nothing about
whether the token is genuine.

### Try them on the sample tokens

```bash
./bash/inspect-jwt.sh      < samples/expired.jwt
py python/inspect_jwt.py   < samples/valid.jwt       # "python3" on Linux/macOS
node node/inspect-jwt.mjs  < samples/alg-none.jwt
jq -Rs -f jq/jwt.jq        < samples/not-yet-valid.jwt
./openssl/verify-jwt.sh --secret demo-secret-do-not-use --alg HS256 < samples/valid.jwt
```

The HS256 samples are signed with the deliberately public secret
`demo-secret-do-not-use`. See [`samples/README.md`](samples/README.md).

---

## 3. Quick one-liners (no script needed)

### PowerShell

```powershell
$token = "eyJhbGciOi..."
$part  = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
$part += '=' * ((4 - $part.Length % 4) % 4)
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
```

### Bash / Git Bash

```bash
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

(`base64 -d` may complain about missing padding but usually still prints the JSON.)

### jq

```bash
echo "$TOKEN" | jq -R 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | . + ("==="[0:((4 - length % 4) % 4)]) | @base64d | fromjson'
```

### Python

```bash
python3 -c "import sys,base64,json; p=sys.argv[1].split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))),indent=2))" "$TOKEN"
```

### Node.js

```bash
node -e "console.log(JSON.parse(Buffer.from(process.argv[1].split('.')[1],'base64url')))" "$TOKEN"
```

### Go

```go
parts := strings.Split(token, ".")
payload, err := base64.RawURLEncoding.DecodeString(parts[1])
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(payload))
```

To actually **verify** a token in Go, use a library such as
[`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) with the
issuer's key.

### Web tools

Sites such as [jwt.io](https://jwt.io) decode tokens in the browser. **Don't paste
production tokens into third-party sites.** A live token can be used by anyone
who sees it. Use one of the local tools instead. See [`cli-tools/`](cli-tools/).

---

## 4. Checklist: validating a token properly

When a service accepts a JWT, it should check **all** of the following, not just decode it:

1. **Signature** is valid, using the issuer's key selected by `kid`.
2. **`alg`** is one you expect. Reject `none`, and don't let the token choose the algorithm freely (this prevents algorithm-confusion attacks).
3. **`iss`** matches the trusted issuer exactly.
4. **`aud`** contains your API's identifier.
5. **`exp`** is in the future and **`nbf`** is in the past, allowing a small clock skew (e.g. 1–5 minutes).
6. **Scopes / roles** allow the requested operation.
7. Optionally, **`jti`** hasn't been seen before or revoked.

---

## 5. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| "expected 3 dot-separated parts" | Token was truncated or copied with extra text, or it's an opaque (non-JWT) access token. |
| Decoding error on the payload | Stray whitespace, quotes or line breaks inside the token. |
| 401 with an unexpired token | Wrong `aud`, wrong `iss`, signing key rotated (unknown `kid`), or missing scope. |
| Token "expired" but just issued | Clock skew between machines. Compare `iat` with your system clock. |

## References

- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7515: JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7516: JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OpenID Connect Core: ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
