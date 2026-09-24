#!/usr/bin/env bash
# inspect-jwt.sh - decode and display the contents of a JWT (JSON Web Token).
#
# Splits the token into header, payload and signature, Base64Url-decodes the
# header and payload, pretty-prints them, and interprets the common time claims
# (exp, iat, nbf, auth_time) as readable UTC/local dates with an expiry status.
#
# It does NOT verify the signature. Do not trust the output for security decisions.
#
# Requires: bash 3.2+, base64, date. Optional: jq (pretty JSON + full claim summary).
# Runs on Linux, macOS, WSL and Git Bash on Windows.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: inspect-jwt.sh [--raw] [--no-color] [TOKEN]

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
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- Options -----------------------------------------------------------------
RAW=0
COLOR=0
[[ -t 1 && -z "${NO_COLOR:-}" ]] && COLOR=1
ARGS=()
for a in "$@"; do
  case "$a" in
    -r|--raw) RAW=1 ;;
    --no-color) COLOR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$a") ;;
  esac
done

if (( COLOR )); then
  C_CYAN=$'\e[36m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_RED=$'\e[31m' C_DIM=$'\e[90m' C_OFF=$'\e[0m'
else
  C_CYAN='' C_GREEN='' C_YELLOW='' C_RED='' C_DIM='' C_OFF=''
fi

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# --- Helpers -----------------------------------------------------------------

read_clipboard() {
  if   command -v pbpaste        >/dev/null 2>&1; then pbpaste
  elif command -v wl-paste       >/dev/null 2>&1; then wl-paste --no-newline 2>/dev/null
  elif command -v xclip          >/dev/null 2>&1; then xclip -o -selection clipboard 2>/dev/null
  elif command -v xsel           >/dev/null 2>&1; then xsel --clipboard --output 2>/dev/null
  elif [[ -r /dev/clipboard ]];                   then cat /dev/clipboard            # Git Bash / Cygwin
  elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile -Command 'Get-Clipboard -Raw' # WSL
  fi
}

# Base64Url-decode one segment, with or without '=' padding.
b64url_decode() {
  local s=${1%%=*}
  s=${s//-/+}
  s=${s//_//}
  case $(( ${#s} % 4 )) in
    2) s+='==' ;;
    3) s+='=' ;;
    1) return 1 ;;
  esac
  # GNU/BusyBox/modern macOS use -d; older macOS uses -D.
  printf '%s' "$s" | base64 -d 2>/dev/null || printf '%s' "$s" | base64 -D 2>/dev/null
}

pretty_json() {
  if (( HAVE_JQ )); then jq . <<<"$1" 2>/dev/null || printf '%s\n' "$1"
  else printf '%s\n' "$1"
  fi
}

# Print a top-level claim as display text (strings unquoted, arrays joined with ", ").
# Without jq only simple string / number / boolean values are found.
claim() { # <json> <key>
  if (( HAVE_JQ )); then
    jq -r --arg k "$2" '
      def show: if type == "string" then . else tojson end;
      if type == "object" and has($k) then
        .[$k] | if type == "array" then map(show) | join(", ") else show end
      else empty end' <<<"$1" 2>/dev/null
  else
    local m
    m=$(grep -oE "\"$2\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[-0-9.eE+]+|true|false)" <<<"$1" | head -n1) || return 0
    m=${m#*:}
    m="${m#"${m%%[![:space:]]*}"}"
    m=${m#\"}; m=${m%\"}
    printf '%s\n' "$m"
  fi
}

# NumericDate -> "YYYY-MM-DD HH:MM:SS UTC  (YYYY-MM-DD HH:MM:SS local)"
GNU_DATE=0
date -u -d @0 >/dev/null 2>&1 && GNU_DATE=1
epoch_fmt() { # <seconds> [-u]
  if (( GNU_DATE )); then date ${2:-} -d "@$1" "+%Y-%m-%d %H:%M:%S"   # GNU date
  else                    date ${2:-} -r "$1"  "+%Y-%m-%d %H:%M:%S"   # BSD / macOS date
  fi
}
format_time() { printf "%s UTC  (%s local)" "$(epoch_fmt "$1" -u)" "$(epoch_fmt "$1")"; }

# Seconds -> "[Nd ]HH:MM:SS"
format_duration() {
  local s=${1#-} d
  d=$(( s / 86400 )); s=$(( s % 86400 ))
  if (( d > 0 )); then
    printf '%dd %02d:%02d:%02d' "$d" $(( s / 3600 )) $(( s % 3600 / 60 )) $(( s % 60 ))
  else
    printf '%02d:%02d:%02d' $(( s / 3600 )) $(( s % 3600 / 60 )) $(( s % 60 ))
  fi
}

row() { printf '%-18s %s\n' "$1:" "$2"; }

# --- Get the token -----------------------------------------------------------
if (( ${#ARGS[@]} > 0 )); then
  TOKEN="${ARGS[*]}"
elif [[ ! -t 0 ]]; then
  TOKEN=$(cat)
else
  TOKEN=""
fi
if [[ -z "${TOKEN//[[:space:]]/}" ]]; then
  TOKEN=$(read_clipboard || true)
  [[ -z "${TOKEN//[[:space:]]/}" ]] && die "No token supplied. Pass it as an argument, pipe it in, or copy it to the clipboard."
  printf '%s(Token read from clipboard)%s\n' "$C_DIM" "$C_OFF" >&2
fi

# Strip "Authorization: Bearer " / "Bearer ", quotes and all whitespace.
shopt -s nocasematch
TOKEN="${TOKEN#"${TOKEN%%[![:space:]]*}"}"
[[ "$TOKEN" =~ ^(authorization:[[:space:]]*)?bearer[[:space:]]+ ]] && TOKEN=${TOKEN:${#BASH_REMATCH[0]}}
shopt -u nocasematch
TOKEN=${TOKEN//[[:space:]]/}
TOKEN=${TOKEN#[\"\']}; TOKEN=${TOKEN%[\"\']}

IFS='.' read -r -a PARTS <<<"$TOKEN"
# `read` drops a trailing empty field (e.g. the empty signature of an alg:none token).
[[ "$TOKEN" == *. ]] && PARTS+=("")
NPARTS=${#PARTS[@]}

if (( NPARTS == 5 )); then
  printf '%sWARNING: Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded.%s\n' "$C_YELLOW" "$C_OFF"
elif (( NPARTS != 3 )); then
  die "Invalid JWT: expected 3 dot-separated parts, found $NPARTS."
fi

# --- Decode ------------------------------------------------------------------
HEADER=$(b64url_decode "${PARTS[0]}") && [[ "$HEADER" == \{* ]] || die "Could not decode header."
PAYLOAD=""
if (( NPARTS == 3 )); then
  PAYLOAD=$(b64url_decode "${PARTS[1]}") && [[ "$PAYLOAD" == \{* ]] || die "Could not decode payload."
fi

if (( RAW )); then
  pretty_json "$HEADER"
  [[ -n "$PAYLOAD" ]] && pretty_json "$PAYLOAD"
  exit 0
fi

# --- Display -----------------------------------------------------------------
printf '\n%s=== HEADER ===%s\n' "$C_CYAN" "$C_OFF"
pretty_json "$HEADER"

if [[ -n "$PAYLOAD" ]]; then
  printf '\n%s=== PAYLOAD ===%s\n' "$C_CYAN" "$C_OFF"
  pretty_json "$PAYLOAD"

  printf '\n%s=== SUMMARY ===%s\n' "$C_CYAN" "$C_OFF"
  (( HAVE_JQ )) || printf '%s(install jq for arrays and the full claim summary)%s\n' "$C_DIM" "$C_OFF"

  LABELS=(iss:Issuer sub:Subject aud:Audience "azp:Authorized party" "jti:Token ID"
          scope:Scope scp:Scopes roles:Roles name:Name email:Email upn:UPN
          preferred_username:Username "tid:Tenant ID" "oid:Object ID"
          "client_id:Client ID" "appid:App ID")
  for entry in "${LABELS[@]}"; do
    v=$(claim "$PAYLOAD" "${entry%%:*}")
    [[ -n "$v" ]] && row "${entry#*:}" "$v"
  done

  IAT="" NBF="" EXP=""
  for entry in "iat:Issued at" "nbf:Not before" "exp:Expires" "auth_time:Auth time"; do
    k=${entry%%:*}
    v=$(claim "$PAYLOAD" "$k")
    [[ -z "$v" ]] && continue
    if [[ "$v" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
      v=${v%%.*}
      row "${entry#*:}" "$(format_time "$v")"
      case $k in iat) IAT=$v ;; nbf) NBF=$v ;; exp) EXP=$v ;; esac
    else
      row "${entry#*:}" "$v (unparseable)"
    fi
  done

  [[ -n "$IAT" && -n "$EXP" ]] && row "Lifetime" "$(format_duration $(( EXP - IAT )))"

  NOW=$(date +%s)
  echo
  if [[ -n "$NBF" ]] && (( NBF > NOW )); then
    printf '%sSTATUS: NOT YET VALID (valid in %s)%s\n' "$C_YELLOW" "$(format_duration $(( NBF - NOW )))" "$C_OFF"
  elif [[ -n "$EXP" ]] && (( EXP <= NOW )); then
    printf '%sSTATUS: EXPIRED (%s ago)%s\n' "$C_RED" "$(format_duration $(( NOW - EXP )))" "$C_OFF"
  elif [[ -n "$EXP" ]]; then
    printf '%sSTATUS: VALID (expires in %s)%s\n' "$C_GREEN" "$(format_duration $(( EXP - NOW )))" "$C_OFF"
  else
    printf "%sSTATUS: No 'exp' claim - token does not expire.%s\n" "$C_YELLOW" "$C_OFF"
  fi
fi

printf '\n%s=== SIGNATURE ===%s\n' "$C_CYAN" "$C_OFF"
ALG=$(claim "$HEADER" alg)
KID=$(claim "$HEADER" kid)
row "Algorithm" "$ALG"
[[ -n "$KID" ]] && row "Key ID (kid)" "$KID"
shopt -s nocasematch
[[ "$ALG" == none ]] && printf "%sWARNING: alg is 'none' - token is unsigned!%s\n" "$C_RED" "$C_OFF"
shopt -u nocasematch
SIG=${PARTS[NPARTS-1]}
row "Signature length" "${#SIG} chars (Base64Url)"
printf '%sSignature NOT verified by this script.%s\n\n' "$C_DIM" "$C_OFF"
