# OpenSSL: `verify-jwt.sh`

The decoders in the other folders show what a token **says**. This script checks
whether the token is **genuine**: it verifies the signature with the shared secret
or the issuer's public key, using only OpenSSL.

| | |
|---|---|
| **Runs on** | Linux, macOS, WSL, Git Bash on Windows (Git for Windows includes OpenSSL) |
| **Needs** | bash, OpenSSL 1.1.1+ (3.x for EdDSA), `base64`, `od`, `sed` |
| **Algorithms** | HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA |

## Usage

```
verify-jwt.sh (--secret S | --secret-file F | --secret-b64 S | --key PEM) [--alg ALG] [TOKEN]

  --secret S         HMAC secret as text                   (HS256/384/512)
  --secret-file F    HMAC secret read from a file (a trailing newline is removed)
  --secret-b64 S     HMAC secret given as Base64 / Base64Url
  --key PEM          public key or X.509 certificate in PEM format (RS*, PS*, ES*, EdDSA)
  --alg ALG          algorithm you EXPECT; the token is rejected if its header says otherwise
```

The token comes from the arguments or from piped stdin, and a `Bearer ` prefix is
stripped.

| Exit code | Meaning |
|-----------|---------|
| `0` | `VALID`: the signature matches |
| `1` | `INVALID`: the signature doesn't match, the algorithm isn't the expected one, or the token is unsigned (`alg: none`) |
| `2` | Usage or input error (missing key, unreadable token, unsupported algorithm, JWE) |

## Examples

Using the [sample tokens](../samples/):

```bash
# HS256 with a shared secret
./verify-jwt.sh --secret demo-secret-do-not-use --alg HS256 < ../samples/valid.jwt
# VALID: signature verified (HS256)
# Note: only the signature was checked - exp, nbf, iss and aud were not.

./verify-jwt.sh --secret wrong-secret < ../samples/valid.jwt
# INVALID: signature does not match (HS256)

# RS256 with a public key (run ../samples/make-samples.sh --rsa first)
./verify-jwt.sh --key ../samples/keys/rs256-public.pem --alg RS256 < ../samples/rs256.jwt

# Unsigned tokens are always rejected
./verify-jwt.sh --secret anything < ../samples/alg-none.jwt
# INVALID: token is unsigned (alg=none)

# Use the exit code in a script
if ./verify-jwt.sh --key issuer.pem --alg RS256 "$TOKEN" > /dev/null; then
  echo "genuine"
fi
```

Keep secrets out of your shell history: prefer `--secret-file`, or read the
secret into a variable with `read -rs SECRET`.

### Why `--alg` matters

Without `--alg`, the script uses whatever algorithm the token's header claims.
A real service must **never** do that. In an *algorithm-confusion* attack, an
attacker changes `RS256` to `HS256` and signs the token with the issuer's *public*
key as the HMAC secret. Always pass the algorithm you expect.

## Getting the issuer's public key

Most identity providers publish their keys as a **JWKS** (JSON Web Key Set), not
as PEM files:

1. Find the `jwks_uri` in `https://<issuer>/.well-known/openid-configuration`.
2. Download the JWKS and choose the key whose `kid` matches the token header's `kid`.
3. Convert it to PEM:
   - If the key has an `x5c` entry (Microsoft Entra ID, Auth0 and others do),
     that's the certificate. Wrap it and pass it straight to `--key`:

     ```bash
     KID=$(../bash/inspect-jwt.sh --raw "$TOKEN" | jq -rs '.[0].kid')
     curl -s "$JWKS_URI" | jq -r --arg kid "$KID" '.keys[] | select(.kid == $kid) | .x5c[0]' \
       | { echo "-----BEGIN CERTIFICATE-----"; fold -w 64; echo "-----END CERTIFICATE-----"; } > issuer.pem
     ./verify-jwt.sh --key issuer.pem --alg RS256 "$TOKEN"
     ```

   - Otherwise (`n`/`e` or `x`/`y` values only), use the `step` CLI, which verifies
     against a JWKS directly. See [`../cli-tools/`](../cli-tools/).

## How it works

JWS signs the exact ASCII bytes `base64url(header) + "." + base64url(payload)`.
The script writes those bytes to a file, decodes the signature, and:

| Algorithm | OpenSSL command |
|-----------|-----------------|
| `HS*` | `openssl dgst -shaNNN -mac HMAC -macopt hexkey:...` and compares the result |
| `RS*` | `openssl dgst -shaNNN -verify pub.pem -signature sig` (PKCS#1 v1.5) |
| `PS*` | same, plus `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest` |
| `ES*` | same as `RS*`, after converting the signature (see below) |
| `EdDSA` | `openssl pkeyutl -verify -rawin` |

**ECDSA gotcha:** in a JWT the ES256 signature is the two 32-byte numbers `r` and
`s` joined together (64 bytes). OpenSSL expects them wrapped in an ASN.1 DER
`SEQUENCE { INTEGER r, INTEGER s }`. The `ecdsa_raw_to_der` function in the script
does that conversion by hand, which shows what that encoding looks like.

## Limitations

- Only the **signature** is checked. It doesn't check `exp`/`nbf`, `iss`, `aud`
  or scopes. Use a decoder for those, or a library that does full validation
  (see the "Going further" section of each language's README).
- It can't decrypt encrypted tokens (JWE).
