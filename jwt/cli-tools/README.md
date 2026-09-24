# Third-party tools

Ready-made tools for decoding and verifying JWTs. Nothing to build: install one
and use it. They are worth knowing when you need something the scripts in this
folder don't do, such as verifying against a JWKS URL or creating tokens for tests.

| Tool | Decode | Verify | JWKS URL | Create tokens | Windows | Linux / macOS |
|------|:------:|:------:|:--------:|:-------------:|:-------:|:-------------:|
| [`jwt-cli`](#jwt-cli) | ✅ | ✅ | – | ✅ | ✅ | ✅ |
| [`step`](#smallstep-step-cli) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| [Web decoders](#web-decoders) | ✅ | ✅ (paste a key) | – | ✅ | browser | browser |

---

## jwt-cli

A small, fast Rust binary: <https://github.com/mike-engel/jwt-cli>

### Install

| Platform | Command |
|----------|---------|
| macOS / Linux (Homebrew) | `brew install mike-engel/jwt-cli/jwt-cli` |
| Windows (Scoop) | `scoop install jwt-cli` |
| Any (Rust toolchain) | `cargo install jwt-cli` |
| Any | Download a binary from the GitHub releases page |

### Use

```bash
# Decode (no verification)
jwt decode "$TOKEN"

# Decode as JSON, for scripts
jwt decode --json "$TOKEN" | jq .payload.sub

# Verify an HS256 token with a secret ("@file" reads it from a file, "b64:..." for Base64)
jwt decode --secret demo-secret-do-not-use "$(cat ../samples/valid.jwt)"

# Verify an RS256 token with a public key
jwt decode --secret @../samples/keys/rs256-public.pem --alg RS256 "$(cat ../samples/rs256.jwt)"

# Create a test token
jwt encode --secret demo-secret-do-not-use --exp=+1h --sub user42 '{"scope":"read"}'
```

Run `jwt decode --help` for all options, since flags change between releases.

---

## Smallstep `step` CLI

A general-purpose PKI tool whose `crypto jwt` subcommands cover JWTs, including
verification against a **remote JWKS**: <https://smallstep.com/docs/step-cli/>

### Install

| Platform | Command |
|----------|---------|
| macOS / Linux (Homebrew) | `brew install step` |
| Debian / Ubuntu | `.deb` package from the [install page](https://smallstep.com/docs/step-cli/installation/) |
| Windows | `winget install Smallstep.step` or `scoop install smallstep/step` |

### Use

```bash
# Decode (the --insecure flag acknowledges that nothing is verified)
echo "$TOKEN" | step crypto jwt inspect --insecure

# Verify signature AND claims (exp, nbf, iss, aud) against the issuer's JWKS
echo "$TOKEN" | step crypto jwt verify \
  --jwks https://login.example.com/.well-known/jwks.json \
  --iss https://login.example.com \
  --aud api

# Verify with a local PEM key
echo "$TOKEN" | step crypto jwt verify --key issuer-public.pem --iss https://login.example.com --aud api

# Create a test token signed with a local key
step crypto jwt sign --key private.pem --iss https://login.example.com --aud api --sub user42 --exp +1h
```

`step crypto jwt verify` does the full validation described in the
[checklist](../README.md#4-checklist-validating-a-token-properly), which makes it
the easiest way to answer "would my API accept this token?" from the command line.

---

## Web decoders

| Site | Notes |
|------|-------|
| <https://jwt.io> | Decodes, verifies with a pasted secret or key, and can create tokens. |
| <https://jwt.ms> | Microsoft's decoder. Explains Entra ID (Azure AD) claims. |

> **Don't paste production tokens into third-party websites.** Anyone who has a
> live token can use it until it expires. Even when a site decodes in the browser,
> you are relying on its code, its analytics and your browser extensions. Use
> them only for test tokens such as the ones in [`../samples/`](../samples/), and
> use a local tool for real ones.

---

## Libraries (for code, not the command line)

When your own service needs to validate tokens, use a maintained library:

| Language | Library |
|----------|---------|
| Go | [`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt), [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx) |
| Python | [PyJWT](https://pyjwt.readthedocs.io/), [joserfc](https://jose.authlib.org/) |
| Node.js | [`jose`](https://github.com/panva/jose) |
| .NET | [`Microsoft.IdentityModel.JsonWebTokens`](https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens) |
| Java | [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt), [jjwt](https://github.com/jwtk/jjwt) |

The "Going further" section of each language's README in this folder has a short example.
