# PowerShell: `Inspect-Jwt.ps1`

Decodes a JWT and prints its header, payload, a claim summary, readable times and
an expiry status. **It does not verify the signature.**

| | |
|---|---|
| **Runs on** | Windows PowerShell 5.1 (built into Windows) and PowerShell 7+ on Windows, Linux and macOS |
| **Needs** | Nothing else. Clipboard input on Linux needs `xclip` or `wl-clipboard`. |

## Usage

```powershell
# Pass the token as an argument ("Bearer " / "Authorization: Bearer " prefixes are stripped)
.\Inspect-Jwt.ps1 "Bearer eyJhbGciOi..."

# Pipe it in
Get-Content token.txt | .\Inspect-Jwt.ps1

# Copy the token to the clipboard, then run with no arguments
.\Inspect-Jwt.ps1

# Only print the decoded header and payload JSON
.\Inspect-Jwt.ps1 $token -Raw

# Built-in help
Get-Help .\Inspect-Jwt.ps1 -Detailed
```

If script execution is blocked, run it with a one-off policy override:

```powershell
powershell -ExecutionPolicy Bypass -File .\Inspect-Jwt.ps1 "eyJhbGciOi..."
```

### On Linux or macOS

Install PowerShell 7 ([instructions](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)),
then run the same script with `pwsh`:

```bash
pwsh ./Inspect-Jwt.ps1 "$TOKEN"
pwsh ./Inspect-Jwt.ps1 < ../samples/expired.jwt   # piping works too
```

## Sample output

```
=== HEADER ===
{
    "alg":  "RS256",
    "typ":  "JWT",
    "kid":  "abc123"
}

=== PAYLOAD ===
{ ... }

=== SUMMARY ===
Issuer:            https://login.example.com
Subject:           user42
Audience:          api, web
Name:              Jane Doe
Issued at:         2026-09-24 11:01:49 UTC  (2026-09-24 07:01:49 local)
Expires:           2026-09-24 12:01:49 UTC  (2026-09-24 08:01:49 local)
Lifetime:          01:00:00

STATUS: VALID (expires in 0.00:49:59)

=== SIGNATURE ===
Algorithm:         RS256
Key ID (kid):      abc123
Signature length:  342 chars (Base64Url)
Signature NOT verified by this script.
```

Durations use .NET's `TimeSpan` format `d.hh:mm:ss`, so `0.00:49:59` means
49 minutes 59 seconds. The other tools in this folder write the same duration as
`00:49:59`, and `26761d 12:58:11` for durations longer than a day.

## How it works

1. Reads the token from the argument, the pipeline, or `Get-Clipboard`.
2. Strips the `Bearer` prefix, quotes and whitespace, then splits on `.`.
3. Converts each Base64Url segment to standard Base64 (`-` → `+`, `_` → `/`, adds
   `=` padding) and decodes it with `[Convert]::FromBase64String`.
4. Parses the JSON with `ConvertFrom-Json` and converts time claims with
   `[DateTimeOffset]::FromUnixTimeSeconds`.

To verify the signature, see [`../openssl/`](../openssl/) or [`../cli-tools/`](../cli-tools/).
