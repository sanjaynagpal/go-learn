# Node.js: `inspect-jwt.mjs`

A single-file Node.js script that decodes a JWT and prints its header, payload, a
claim summary, readable times and an expiry status. It needs no npm packages.
**It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Windows, Linux, macOS |
| **Needs** | Node.js 16+ (for `Buffer`'s `base64url` encoding). No `npm install`. |

## Usage

```
node inspect-jwt.mjs [--raw] [--no-color] [TOKEN]

  -r, --raw       print only the decoded header and payload JSON
      --no-color  disable coloured output (also honoured: NO_COLOR env var)
  -h, --help      show this help
```

The token is read from the arguments, then from piped stdin, then from the clipboard.

```bash
node inspect-jwt.mjs eyJhbGciOi...
node inspect-jwt.mjs "Authorization: Bearer eyJhbGciOi..."
node inspect-jwt.mjs < ../samples/not-yet-valid.jwt
node inspect-jwt.mjs --raw "$TOKEN"
node inspect-jwt.mjs                      # reads the clipboard
```

PowerShell:

```powershell
node inspect-jwt.mjs $token
Get-Content token.txt | node inspect-jwt.mjs
```

On Linux/macOS you can also run it directly: `chmod +x inspect-jwt.mjs && ./inspect-jwt.mjs "$TOKEN"`.

### Add it as an npm script

In a project that already uses Node, point a `package.json` script at the file:

```json
{
  "scripts": {
    "jwt": "node ../jwt/node/inspect-jwt.mjs"
  }
}
```

```bash
npm run jwt -- "$TOKEN"
```

## Sample output

The output matches the other decoders:

```
=== SUMMARY ===
Issuer:            https://login.example.com
Subject:           svc-batch
Audience:          api
Issued at:         2026-09-24 11:01:49 UTC  (2026-09-24 07:01:49 local)
Not before:        2099-01-01 00:00:00 UTC  (2098-12-31 19:00:00 local)
Expires:           2100-01-01 00:00:00 UTC  (2099-12-31 19:00:00 local)
Lifetime:          26761d 12:58:11

STATUS: NOT YET VALID (valid in 26396d 12:21:33)
```

Exit code is `0` on success and `1` if the token can't be read or decoded.

## Notes

- `JSON.parse` turns numbers into IEEE-754 doubles, so integer claims larger than
  2^53 (rare, but some systems use them for IDs) lose precision in the
  pretty-printed payload. Use `--raw` output from the [Go](../go/) or
  [Python](../python/) tool if you need them exactly.
- JavaScript objects list integer-like keys (`"1"`, `"2"`) before other keys, so
  those keys may appear in a different order than in the token.

## Going further: verifying the signature

Use [`jose`](https://github.com/panva/jose) (`npm install jose`):

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = createRemoteJWKSet(new URL('https://login.example.com/.well-known/jwks.json'));
const { payload } = await jwtVerify(token, jwks, {
  issuer: 'https://login.example.com',
  audience: 'api',
  algorithms: ['RS256'],
  clockTolerance: '2m',
});
```

To check a signature from the command line, see [`../openssl/`](../openssl/).
