# jwt.jq - decode a JWT with jq and emit a single JSON report.
#
#   jq -Rs -f jwt.jq < token.txt
#   echo "$TOKEN" | jq -Rs -f jwt.jq
#   echo "$TOKEN" | jq -Rs -f jwt.jq --arg mode raw     # header + payload only
#
# -R reads the input as text, -s slurps it into one string (so a token that is
# wrapped across lines still works).
#
# The signature is NOT verified. Needs jq 1.6+ (or gojq / jaq).

# Base64Url-decode one segment, with or without '=' padding.
def b64url_decode:
  gsub("="; "") | gsub("-"; "+") | gsub("_"; "/")
  | . as $s
  | if length % 4 == 1 then error("invalid Base64Url segment length") else . end
  | . + ("===" | .[0:((4 - ($s | length) % 4) % 4)]) | @base64d;

# Seconds -> "[Nd ]HH:MM:SS" (sign dropped).
def fmt_duration:
  (if . < 0 then -. else . end | floor) as $s
  | ($s / 86400 | floor) as $d
  | ($s % 86400) as $r
  | [($r / 3600 | floor), ($r % 3600 / 60 | floor), ($r % 60)]
  | map(tostring | if length < 2 then "0" + . else . end)
  | join(":")
  | if $d > 0 then "\($d)d " + . else . end;

# NumericDate -> "YYYY-MM-DD HH:MM:SS UTC  (YYYY-MM-DD HH:MM:SS local)"
def fmt_time:
  floor | "\(strftime("%Y-%m-%d %H:%M:%S")) UTC  (\(strflocaltime("%Y-%m-%d %H:%M:%S")) local)";

def is_num: type == "number";

($ARGS.named.mode // "full") as $mode
# Strip "Authorization: Bearer " / "Bearer ", surrounding quotes and all whitespace.
| sub("^\\s+"; "")
| sub("^(authorization:\\s*)?bearer\\s+"; ""; "i")
| gsub("\\s"; "")
| gsub("^[\"']+|[\"']+$"; "")
| split(".") as $parts
| ($parts | length) as $n
| if $n != 3 and $n != 5 then error("Invalid JWT: expected 3 dot-separated parts, found \($n).") else . end
| ($parts[0] | b64url_decode | fromjson) as $header
| if $n == 5 then
    { warning: "Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded.",
      header: $header }
  else
    ($parts[1] | b64url_decode | fromjson) as $payload
    | if ($payload | type) != "object" then error("Payload is not a JSON object.") else . end
    | if $mode == "raw" then
        { header: $header, payload: $payload }
      else
        now as $now
        | {
            header: $header,
            payload: $payload,
            times: (reduce ("iat", "nbf", "exp", "auth_time") as $k ({};
                      if ($payload[$k] | is_num) then . + { ($k): ($payload[$k] | fmt_time) } else . end)),
            lifetime: (if ($payload.iat | is_num) and ($payload.exp | is_num)
                       then $payload.exp - $payload.iat | fmt_duration else null end),
            status: (
              if ($payload.nbf | is_num) and $payload.nbf > $now then
                "NOT YET VALID (valid in \($payload.nbf - $now | fmt_duration))"
              elif ($payload.exp | is_num) and $payload.exp <= $now then
                "EXPIRED (\($now - $payload.exp | fmt_duration) ago)"
              elif ($payload.exp | is_num) then
                "VALID (expires in \($payload.exp - $now | fmt_duration))"
              else
                "No 'exp' claim - token does not expire."
              end),
            signature: {
              alg: $header.alg,
              kid: $header.kid,
              length: ($parts[2] | length),
              verified: false
            }
          }
        | if ($header.alg | ascii_downcase? // "") == "none"
          then .warning = "alg is 'none' - token is unsigned!" else . end
        | .signature |= with_entries(select(.value != null))
        | with_entries(select(.value != null))
      end
  end
