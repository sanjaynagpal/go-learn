#!/usr/bin/env bash
# Regenerates the sample tokens in this folder.
#
#   ./make-samples.sh          HS256 samples (committed to the repo)
#   ./make-samples.sh --rsa    also creates an RSA key pair in keys/ and an RS256
#                              token in rs256.jwt (both git-ignored)
#
# Requires: bash, openssl, base64, tr.
# The HS256 secret is deliberately public. These tokens are for testing only.
set -euo pipefail
cd "$(dirname "$0")"

SECRET='demo-secret-do-not-use'

# Base64Url-encode stdin: standard Base64, no padding, no line breaks, URL-safe alphabet.
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }

# make_hs256 <header-json> <payload-json>
make_hs256() {
  local h p s
  h=$(printf '%s' "$1" | b64url)
  p=$(printf '%s' "$2" | b64url)
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}

HS='{"alg":"HS256","typ":"JWT","kid":"demo-hs256"}'

# Valid until 2100-01-01.
make_hs256 "$HS" '{"iss":"https://login.example.com","sub":"user42","aud":["api","web"],"iat":1790247709,"nbf":1790247709,"exp":4102444800,"jti":"9f1c2e7a-demo","scope":"read write","name":"Jane Doe","email":"jane@example.com","roles":["reader","writer"]}' > valid.jwt

# Expired in November 2023, one-hour lifetime.
make_hs256 "$HS" '{"iss":"https://login.example.com","sub":"user42","aud":"api","iat":1700000000,"exp":1700003600,"client_id":"cli-app"}' > expired.jwt

# Not valid before 2099-01-01.
make_hs256 "$HS" '{"iss":"https://login.example.com","sub":"svc-batch","aud":"api","iat":1790247709,"nbf":4070908800,"exp":4102444800}' > not-yet-valid.jwt

# Unsigned token: alg "none" and an empty signature segment.
printf '%s.%s.\n' \
  "$(printf '%s' '{"alg":"none","typ":"JWT"}' | b64url)" \
  "$(printf '%s' '{"sub":"attacker","admin":true}' | b64url)" > alg-none.jwt

# Encrypted JWE shape: 5 parts. Only the header is readable; the rest is random.
printf '%s.%s.%s.%s.%s\n' \
  "$(printf '%s' '{"alg":"RSA-OAEP","enc":"A256GCM","kid":"enc-key-1"}' | b64url)" \
  "$(openssl rand 256 | b64url)" "$(openssl rand 12 | b64url)" \
  "$(openssl rand 48 | b64url)" "$(openssl rand 16 | b64url)" > encrypted-jwe.jwt

if [[ "${1:-}" == "--rsa" ]]; then
  mkdir -p keys
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/rs256-private.pem 2>/dev/null
  openssl pkey -in keys/rs256-private.pem -pubout -out keys/rs256-public.pem
  h=$(printf '%s' '{"alg":"RS256","typ":"JWT","kid":"demo-rs256"}' | b64url)
  p=$(printf '%s' '{"iss":"https://login.example.com","sub":"user42","aud":"api","iat":1790247709,"exp":4102444800}' | b64url)
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -sign keys/rs256-private.pem -binary | b64url)
  printf '%s.%s.%s\n' "$h" "$p" "$s" > rs256.jwt
  echo "Wrote keys/rs256-private.pem, keys/rs256-public.pem, rs256.jwt"
fi

echo "Wrote valid.jwt, expired.jwt, not-yet-valid.jwt, alg-none.jwt, encrypted-jwe.jwt"
