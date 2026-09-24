<#
.SYNOPSIS
    Decodes and displays the contents of a JWT (JSON Web Token).

.DESCRIPTION
    Splits a JWT into header, payload and signature, Base64Url-decodes the header
    and payload, pretty-prints them as JSON, and interprets common time claims
    (exp, iat, nbf, auth_time) as readable UTC/local dates with an expiry status.

    NOTE: This script does NOT verify the signature. Do not trust the contents
    for security decisions based on this output alone.

.PARAMETER Token
    The JWT string. A leading "Bearer " prefix is stripped automatically.
    Can also be piped in. If omitted, the clipboard is used.

.PARAMETER Raw
    Output only the decoded header and payload JSON (no summary).

.EXAMPLE
    .\Inspect-Jwt.ps1 eyJhbGciOiJIUzI1NiIs...

.EXAMPLE
    .\Inspect-Jwt.ps1 "Bearer eyJhbGciOiJIUzI1NiIs..."

.EXAMPLE
    Get-Content token.txt | .\Inspect-Jwt.ps1

.EXAMPLE
    # Copy a token to the clipboard, then:
    .\Inspect-Jwt.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [string]$Token,

    [switch]$Raw
)

function ConvertFrom-Base64Url {
    param([string]$Value)
    $s = $Value.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) {
        2 { $s += '==' }
        3 { $s += '=' }
        1 { throw "Invalid Base64Url segment length." }
    }
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}

function Format-Json {
    param([string]$Json)
    try {
        $Json | ConvertFrom-Json | ConvertTo-Json -Depth 32
    } catch {
        $Json
    }
}

function Convert-UnixTime {
    param($Seconds)
    [DateTimeOffset]::FromUnixTimeSeconds([long]$Seconds)
}

# --- Get the token -----------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Token)) {
    try { $Token = Get-Clipboard -Raw } catch { }
    if ([string]::IsNullOrWhiteSpace($Token)) {
        Write-Error "No token supplied. Pass it as an argument, pipe it in, or copy it to the clipboard."
        exit 1
    }
    Write-Host "(Token read from clipboard)" -ForegroundColor DarkGray
}

$Token = $Token.Trim() -replace '^(?i)(Authorization:\s*)?Bearer\s+', ''
$Token = $Token.Trim().Trim('"', "'") -replace '\s', ''

$parts = $Token.Split('.')
if ($parts.Count -eq 5) {
    Write-Warning "Token has 5 parts - this looks like an encrypted JWE. Only the header can be decoded."
} elseif ($parts.Count -ne 3) {
    Write-Error "Invalid JWT: expected 3 dot-separated parts, found $($parts.Count)."
    exit 1
}

# --- Decode ------------------------------------------------------------------
try {
    $headerJson = ConvertFrom-Base64Url $parts[0]
    $header     = $headerJson | ConvertFrom-Json
} catch {
    Write-Error "Could not decode header: $_"
    exit 1
}

$payloadJson = $null
$payload     = $null
if ($parts.Count -eq 3) {
    try {
        $payloadJson = ConvertFrom-Base64Url $parts[1]
        $payload     = $payloadJson | ConvertFrom-Json
    } catch {
        Write-Error "Could not decode payload: $_"
        exit 1
    }
}

if ($Raw) {
    Format-Json $headerJson
    if ($payloadJson) { Format-Json $payloadJson }
    exit 0
}

# --- Display -----------------------------------------------------------------
Write-Host ""
Write-Host "=== HEADER ===" -ForegroundColor Cyan
Format-Json $headerJson

if ($payloadJson) {
    Write-Host ""
    Write-Host "=== PAYLOAD ===" -ForegroundColor Cyan
    Format-Json $payloadJson

    Write-Host ""
    Write-Host "=== SUMMARY ===" -ForegroundColor Cyan

    $labels = [ordered]@{
        iss = 'Issuer'; sub = 'Subject'; aud = 'Audience'; azp = 'Authorized party'
        jti = 'Token ID'; scope = 'Scope'; scp = 'Scopes'; roles = 'Roles'
        name = 'Name'; email = 'Email'; upn = 'UPN'; preferred_username = 'Username'
        tid = 'Tenant ID'; oid = 'Object ID'; client_id = 'Client ID'; appid = 'App ID'
    }
    $names = $payload.PSObject.Properties.Name
    foreach ($k in $labels.Keys) {
        if ($names -contains $k) {
            $v = $payload.$k
            if ($v -is [array]) { $v = $v -join ', ' }
            "{0,-18} {1}" -f ($labels[$k] + ':'), $v
        }
    }

    $now = [DateTimeOffset]::UtcNow
    $timeClaims = [ordered]@{ iat = 'Issued at'; nbf = 'Not before'; exp = 'Expires'; auth_time = 'Auth time' }
    foreach ($k in $timeClaims.Keys) {
        if ($names -contains $k) {
            try {
                $dt = Convert-UnixTime $payload.$k
                "{0,-18} {1:yyyy-MM-dd HH:mm:ss} UTC  ({2:yyyy-MM-dd HH:mm:ss} local)" -f ($timeClaims[$k] + ':'), $dt.UtcDateTime, $dt.LocalDateTime
            } catch {
                "{0,-18} {1} (unparseable)" -f ($timeClaims[$k] + ':'), $payload.$k
            }
        }
    }

    if ($names -contains 'iat' -and $names -contains 'exp') {
        $life = (Convert-UnixTime $payload.exp) - (Convert-UnixTime $payload.iat)
        "{0,-18} {1}" -f 'Lifetime:', $life
    }

    Write-Host ""
    if ($names -contains 'nbf' -and (Convert-UnixTime $payload.nbf) -gt $now) {
        Write-Host "STATUS: NOT YET VALID (valid in $((Convert-UnixTime $payload.nbf) - $now))" -ForegroundColor Yellow
    } elseif ($names -contains 'exp') {
        $exp = Convert-UnixTime $payload.exp
        if ($exp -le $now) {
            Write-Host ("STATUS: EXPIRED ({0:d\.hh\:mm\:ss} ago)" -f ($now - $exp)) -ForegroundColor Red
        } else {
            Write-Host ("STATUS: VALID (expires in {0:d\.hh\:mm\:ss})" -f ($exp - $now)) -ForegroundColor Green
        }
    } else {
        Write-Host "STATUS: No 'exp' claim - token does not expire." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== SIGNATURE ===" -ForegroundColor Cyan
"Algorithm:         $($header.alg)"
if ($header.kid) { "Key ID (kid):      $($header.kid)" }
if ($header.alg -eq 'none') {
    Write-Host "WARNING: alg is 'none' - token is unsigned!" -ForegroundColor Red
}
$sig = $parts[-1]
"Signature length:  $($sig.Length) chars (Base64Url)"
Write-Host "Signature NOT verified by this script." -ForegroundColor DarkYellow
Write-Host ""
