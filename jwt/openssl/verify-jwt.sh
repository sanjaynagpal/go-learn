#!/usr/bin/env bash
# verify-jwt.sh - verify a JWT's signature with OpenSSL.
#
# Supports HS256/384/512 (shared secret), RS256/384/512 and PS256/384/512 (RSA),
# ES256/384/512 (ECDSA) and EdDSA (Ed25519/Ed448) with a PEM public key or certificate.
#
# Only the signature is checked. Claims (exp, nbf, iss, aud, ...) are not - use one
# of the inspect tools in the sibling folders to read them.
#
# Exit codes: 0 = signature valid, 1 = signature invalid, 2 = usage / input error.
#
# Requires: bash, openssl 1.1.1+ (3.x for EdDSA), base64, od, sed, tr.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: verify-jwt.sh (--secret S | --secret-file F | --secret-b64 S | --key PEM) [--alg ALG] [TOKEN]

Verifies the signature of a JWT. The token is read from the arguments, or from
standard input when it is piped. A "Bearer " prefix is stripped.

Key options (one is required):
  --secret S         HMAC secret as text                   (HS256/384/512)
  --secret-file F    HMAC secret read from a file (a trailing newline is removed)
  --secret-b64 S     HMAC secret given as Base64 / Base64Url
  --key PEM          public key or X.509 certificate in PEM format (RS*, PS*, ES*, EdDSA)

Other options:
  --alg ALG          algorithm you EXPECT. The token is rejected if its header says
                     otherwise. Recommended: never let the token pick its own algorithm.
  -h, --help         show this help
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

SECRET_HEX="" KEY="" EXPECT_ALG="" ARGS=()
to_hex() { od -An -v -tx1 | tr -d ' \n'; }

while (( $# > 0 )); do
  case "$1" in
    --secret)      [[ $# -ge 2 ]] || die "--secret needs a value"; SECRET_HEX=$(printf '%s' "$2" | to_hex); shift ;;
    --secret-file) [[ -r ${2:-} ]] || die "cannot read secret file '${2:-}'"
                   SECRET_HEX=$(printf '%s' "$(cat "$2")" | to_hex); shift ;;   # $(...) drops trailing newlines
    --secret-b64)  [[ $# -ge 2 ]] || die "--secret-b64 needs a value"; B64_SECRET=$2; shift ;;
    --key)         [[ -r ${2:-} ]] || die "cannot read key file '${2:-}'"; KEY=$2; shift ;;
    --alg)         [[ $# -ge 2 ]] || die "--alg needs a value"; EXPECT_ALG=$2; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             ARGS+=("$1") ;;
  esac
  shift
done

# --- Helpers -----------------------------------------------------------------

b64url_encode() { base64 | tr -d '\n=' | tr '+/' '-_'; }

# Base64Url-decode one segment (with or without padding) to stdout as bytes.
b64url_decode() {
  local s=${1%%=*}
  s=${s//-/+}; s=${s//_//}
  case $(( ${#s} % 4 )) in 2) s+='==' ;; 3) s+='=' ;; 1) return 1 ;; esac
  printf '%s' "$s" | base64 -d 2>/dev/null || printf '%s' "$s" | base64 -D 2>/dev/null
}

hex_to_bin() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")"; }

der_len() { if (( $1 < 128 )); then printf '%02x' "$1"; else printf '81%02x' "$1"; fi; }

# One big-endian unsigned integer (hex) -> DER INTEGER (hex).
der_int() {
  local h=$1
  while (( ${#h} > 2 )) && [[ ${h:0:2} == 00 ]]; do h=${h:2}; done
  (( 16#${h:0:1} >= 8 )) && h="00$h"
  printf '02%s%s' "$(der_len $(( ${#h} / 2 )))" "$h"
}

# JWS ECDSA signatures are raw r||s; OpenSSL expects an ASN.1 DER SEQUENCE { r, s }.
ecdsa_raw_to_der() {
  local hex=$1 half=$(( ${#1} / 2 )) body
  body="$(der_int "${hex:0:half}")$(der_int "${hex:half}")"
  printf '30%s%s' "$(der_len $(( ${#body} / 2 )))" "$body"
}

# --- Token -------------------------------------------------------------------
if (( ${#ARGS[@]} > 0 )); then
  TOKEN="${ARGS[*]}"
elif [[ ! -t 0 ]]; then
  TOKEN=$(cat)
else
  usage >&2; exit 2
fi

shopt -s nocasematch
TOKEN="${TOKEN#"${TOKEN%%[![:space:]]*}"}"
[[ "$TOKEN" =~ ^(authorization:[[:space:]]*)?bearer[[:space:]]+ ]] && TOKEN=${TOKEN:${#BASH_REMATCH[0]}}
shopt -u nocasematch
TOKEN=${TOKEN//[[:space:]]/}
TOKEN=${TOKEN#[\"\']}; TOKEN=${TOKEN%[\"\']}

IFS='.' read -r H P S EXTRA <<<"$TOKEN"
[[ -n "$H" && -n "$P" && -z "${EXTRA:-}" && "$TOKEN" == *.*.* ]] \
  || die "expected a signed JWT with 3 dot-separated parts (encrypted 5-part JWEs cannot be verified here)"

HEADER=$(b64url_decode "$H") || die "could not decode header"
ALG=$(grep -oE '"alg"[[:space:]]*:[[:space:]]*"[^"]*"' <<<"$HEADER" | sed -E 's/.*"([^"]*)"$/\1/')
[[ -n "$ALG" ]] || die "header has no 'alg'"

if [[ -n "$EXPECT_ALG" && "$ALG" != "$EXPECT_ALG" ]]; then
  printf 'INVALID: token says alg=%s but %s was expected\n' "$ALG" "$EXPECT_ALG"
  exit 1
fi
[[ "$ALG" == none || -z "$S" ]] && { echo "INVALID: token is unsigned (alg=$ALG)"; exit 1; }

if [[ -n "${B64_SECRET:-}" ]]; then
  SECRET_HEX=$(b64url_decode "$B64_SECRET" | to_hex) || die "--secret-b64 is not valid Base64"
fi

# --- Verify ------------------------------------------------------------------
TMP=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$TMP"' EXIT

printf '%s' "$H.$P" > "$TMP/input"
b64url_decode "$S" > "$TMP/sig" || die "could not decode signature"

pubkey() {
  [[ -n "$KEY" ]] || die "$ALG needs a public key: pass --key PEM"
  if grep -q 'BEGIN CERTIFICATE' "$KEY"; then
    openssl x509 -in "$KEY" -pubkey -noout > "$TMP/pub.pem" || die "could not read certificate"
  else
    openssl pkey -pubin -in "$KEY" -out "$TMP/pub.pem" 2>/dev/null \
      || openssl pkey -in "$KEY" -pubout -out "$TMP/pub.pem" 2>/dev/null \
      || die "could not read public key from $KEY"
  fi
  printf '%s' "$TMP/pub.pem"
}

OK=1
case "$ALG" in
  HS256|HS384|HS512)
    [[ -n "$SECRET_HEX" ]] || die "$ALG needs a shared secret: pass --secret, --secret-file or --secret-b64"
    EXPECTED=$(openssl dgst "-sha${ALG:2}" -mac HMAC -macopt "hexkey:$SECRET_HEX" -binary < "$TMP/input" | b64url_encode)
    [[ "$EXPECTED" == "${S%%=*}" ]] && OK=0
    ;;
  RS256|RS384|RS512)
    PUB=$(pubkey) || exit 2
    openssl dgst "-sha${ALG:2}" -verify "$PUB" -signature "$TMP/sig" "$TMP/input" >/dev/null 2>&1 && OK=0
    ;;
  PS256|PS384|PS512)
    PUB=$(pubkey) || exit 2
    openssl dgst "-sha${ALG:2}" -verify "$PUB" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
      -signature "$TMP/sig" "$TMP/input" >/dev/null 2>&1 && OK=0
    ;;
  ES256|ES384|ES512)
    PUB=$(pubkey) || exit 2
    hex_to_bin "$(ecdsa_raw_to_der "$(to_hex < "$TMP/sig")")" > "$TMP/sig.der"
    openssl dgst "-sha${ALG:2}" -verify "$PUB" -signature "$TMP/sig.der" "$TMP/input" >/dev/null 2>&1 && OK=0
    ;;
  EdDSA|Ed25519|Ed448)
    PUB=$(pubkey) || exit 2
    openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$TMP/input" -sigfile "$TMP/sig" >/dev/null 2>&1 && OK=0
    ;;
  *)
    die "unsupported algorithm '$ALG'"
    ;;
esac

if (( OK == 0 )); then
  echo "VALID: signature verified ($ALG)"
  echo "Note: only the signature was checked - exp, nbf, iss and aud were not."
  exit 0
fi
echo "INVALID: signature does not match ($ALG)"
exit 1
