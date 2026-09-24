# Sample tokens

Test tokens for trying out the tools in this folder. **They are not real
credentials.** The HS256 tokens are signed with the deliberately public secret
`demo-secret-do-not-use`.

| File | What it shows | Expected status |
|------|---------------|-----------------|
| [`valid.jwt`](valid.jwt) | Typical access token: `iss`, `sub`, array `aud`, `scope`, `roles`, `email`; expires 2100-01-01 | **VALID** |
| [`expired.jwt`](expired.jwt) | One-hour token that expired in November 2023; single-string `aud`, `client_id` | **EXPIRED** |
| [`not-yet-valid.jwt`](not-yet-valid.jwt) | `nbf` set to 2099-01-01 | **NOT YET VALID** |
| [`alg-none.jwt`](alg-none.jwt) | Unsigned token (`"alg":"none"`, empty signature) claiming `"admin": true` | No `exp`; `alg: none` warning |
| [`encrypted-jwe.jwt`](encrypted-jwe.jwt) | 5-part encrypted token (JWE). Only the header can be read. | JWE warning |

```bash
../bash/inspect-jwt.sh < expired.jwt
../openssl/verify-jwt.sh --secret demo-secret-do-not-use --alg HS256 < valid.jwt
```

```powershell
..\powershell\Inspect-Jwt.ps1 (Get-Content .\expired.jwt)
```

## Regenerating

```bash
./make-samples.sh          # rewrites the five tokens above (needs bash + openssl)
./make-samples.sh --rsa    # also creates keys/rs256-*.pem and rs256.jwt
```

The RSA key pair and `rs256.jwt` are created locally and are git-ignored, so no
private key is ever committed. The JWE's encrypted parts are random bytes, so that
file changes on every run.
