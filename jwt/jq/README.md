# jq: `jwt.jq`

A jq filter that decodes a JWT and outputs **one JSON document**: header, payload,
readable times, lifetime, status and signature details. It suits scripts and
CI pipelines better than the text output of the other tools.
**It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Anywhere jq runs: Windows, Linux, macOS |
| **Needs** | jq 1.6+ (also works with [gojq](https://github.com/itchyny/gojq)) |

Install jq: `sudo apt install jq` · `sudo dnf install jq` · `brew install jq` · `winget install jqlang.jq`

## Usage

```bash
jq -Rs -f jwt.jq < token.txt
echo "$TOKEN" | jq -Rs -f jwt.jq
echo "$TOKEN" | jq -Rs -f jwt.jq --arg mode raw       # header + payload only
```

- `-R` reads the input as raw text rather than JSON.
- `-s` slurps all input into one string, so a token wrapped across lines still works.
- `-f jwt.jq` loads the filter from the file (use the full path when running from
  another folder).

PowerShell:

```powershell
$token | jq -Rs -f jwt.jq
Get-Content token.txt -Raw | jq -Rs -f jwt.jq
```

`Bearer ` / `Authorization: Bearer `, surrounding quotes and whitespace are
stripped, as in the other tools.

## Sample output

```
$ jq -Rs -f jwt.jq < ../samples/expired.jwt
{
  "header": { "alg": "HS256", "typ": "JWT", "kid": "demo-hs256" },
  "payload": {
    "iss": "https://login.example.com",
    "sub": "user42",
    "aud": "api",
    "iat": 1700000000,
    "exp": 1700003600,
    "client_id": "cli-app"
  },
  "times": {
    "iat": "2023-11-14 22:13:20 UTC  (2023-11-14 17:13:20 local)",
    "exp": "2023-11-14 23:13:20 UTC  (2023-11-14 18:13:20 local)"
  },
  "lifetime": "01:00:00",
  "status": "EXPIRED (1044d 12:24:55 ago)",
  "signature": { "alg": "HS256", "kid": "demo-hs256", "length": 43, "verified": false }
}
```

A `warning` field is added for `alg: none` tokens and for 5-part encrypted tokens
(JWE). For a JWE, only `warning` and `header` are returned. Invalid input makes jq
exit with a non-zero code and an error message.

## Using the output in scripts

Because the output is JSON, you can chain it into another `jq` call:

```bash
# Who is the token for, and when does it expire?
jq -Rs -f jwt.jq < token.txt | jq -r '"\(.payload.sub)  \(.times.exp)"'

# Fail a CI step if the token has expired
jq -Rs -f jwt.jq < token.txt | jq -e '.status | startswith("VALID")' > /dev/null \
  || { echo "token expired"; exit 1; }

# Does the token have the "write" scope?
jq -Rs -f jwt.jq < token.txt | jq -e '.payload.scope | split(" ") | index("write")' > /dev/null
```

## One-liner without the file

```bash
echo "$TOKEN" | jq -R 'split(".")[1] | gsub("-";"+") | gsub("_";"/") | . + ("==="[0:((4 - length % 4) % 4)]) | @base64d | fromjson'
```

## How it works

jq has a built-in `@base64d` but no Base64Url decoder, so `b64url_decode` in the
filter:

1. swaps `-` → `+` and `_` → `/`,
2. adds back the `=` padding that JWT leaves out,
3. calls `@base64d` and then `fromjson`.

`now`, `strftime` and `strflocaltime` turn the time claims into readable dates.
