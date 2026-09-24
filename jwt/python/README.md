# Python: `inspect_jwt.py`

A single-file Python script that decodes a JWT and prints its header, payload, a
claim summary, readable times and an expiry status. It uses only the standard
library. **It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Windows, Linux, macOS |
| **Needs** | Python 3.8+. No `pip install` needed. |

## Usage

```
inspect_jwt.py [-h] [-r] [--no-color] [token ...]

  -r, --raw       print only the decoded header and payload JSON
  --no-color      disable coloured output (also: NO_COLOR env var)
```

The token is read from the arguments, then from piped stdin, then from the clipboard.

Linux / macOS:

```bash
python3 inspect_jwt.py eyJhbGciOi...
python3 inspect_jwt.py "Bearer eyJhbGciOi..."
python3 inspect_jwt.py < ../samples/expired.jwt
python3 inspect_jwt.py --raw "$TOKEN"

# Or make it executable
chmod +x inspect_jwt.py && ./inspect_jwt.py "$TOKEN"
```

Windows (PowerShell or cmd). `py` is the Python launcher installed with Python:

```powershell
py inspect_jwt.py $token
Get-Content token.txt | py inspect_jwt.py
py inspect_jwt.py            # reads the clipboard
```

The clipboard is read with `Get-Clipboard` on Windows, `pbpaste` on macOS, and
`wl-paste`, `xclip` or `xsel` on Linux (or `powershell.exe` under WSL).

## Sample output

```
> py inspect_jwt.py (Get-Content ..\samples\valid.jwt)

=== HEADER ===
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "demo-hs256"
}

=== PAYLOAD ===
{ ... }

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

STATUS: VALID (expires in 26761d 12:21:33)

=== SIGNATURE ===
Algorithm:         HS256
Key ID (kid):      demo-hs256
Signature length:  43 chars (Base64Url)
Signature NOT verified by this script.
```

Exit code is `0` on success and `1` if the token can't be read or decoded.

## Using it as a module

The functions can be imported from other Python code:

```python
from inspect_jwt import clean_token, decode_json_segment

parts = clean_token(raw).split(".")
claims = decode_json_segment(parts[1], "payload")
print(claims["sub"], claims.get("scope"))
```

## Going further: verifying the signature

Use [PyJWT](https://pyjwt.readthedocs.io/) (`pip install "pyjwt[crypto]"`):

```python
import jwt
from jwt import PyJWKClient

signing_key = PyJWKClient("https://login.example.com/.well-known/jwks.json").get_signing_key_from_jwt(token)
claims = jwt.decode(token, signing_key.key, algorithms=["RS256"],
                    audience="api", issuer="https://login.example.com", leeway=120)
```

`jwt.decode` checks the signature, `exp`, `nbf`, `aud` and `iss` in one call.
To check a signature from the command line, see [`../openssl/`](../openssl/).
