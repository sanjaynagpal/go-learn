#Requires -Version 5.1
<#
.SYNOPSIS
    Checks a downloaded Windows executable BEFORE you run it. The file is never executed.

.DESCRIPTION
    Checks run:
      1. File identity   - SHA-256 (optionally compared with the vendor's published hash), PE header,
                           architecture, .NET, exploit-mitigation flags, deceptive file names,
                           Mark of the Web (where it was downloaded from), hidden data streams.
      2. Code signature  - Authenticode status, signer and issuer, timestamp, EV certificate,
                           certificate chain with online revocation check, signer vs. version-info
                           company name, optional expected-publisher check.
      3. Antivirus       - Microsoft Defender on-demand scan of just this file (does not quarantine it).
      4. App Control     - App Control for Business (WDAC) user-mode enforcement, active CI policies,
                           Smart App Control state, AppLocker effective-policy test, and past
                           Code Integrity block or audit events for this file. Gives a prediction of
                           whether the file will be blocked. Also the Group Policy blocks behind
                           "This program is blocked by group policy": Software Restriction Policies
                           level, AppLocker block events, Explorer DisallowRun/RestrictRun lists.
      5. Permissions     - Owner and ACL, whether you have Execute rights, whether broad groups
                           (Everyone, Users, ...) can modify the file or plant DLLs next to it.

    Exit code: 0 = no problems found, 1 = warnings to review, 2 = failures (do not run).

.PARAMETER Path
    The executable (.exe, .msi, .dll, ...) to check.

.PARAMETER ExpectedSha256
    The SHA-256 hash the vendor publishes on their download page.

.PARAMETER ExpectedPublisher
    Text the signer name must contain, for example "Mozilla Corporation".

.PARAMETER SkipDefenderScan
    Do not run the Microsoft Defender scan.

.PARAMETER SkipRevocationCheck
    Do not contact the certificate authority to check revocation (offline use).

.PARAMETER ReportPath
    Optional path to save the findings as .json or .csv.

.EXAMPLE
    .\Test-ExecutableSafety.ps1 -Path "$env:USERPROFILE\Downloads\setup.exe"

.EXAMPLE
    .\Test-ExecutableSafety.ps1 .\setup.exe -ExpectedSha256 3A7B... -ExpectedPublisher "Contoso Ltd"

.NOTES
    Run in Windows PowerShell 5.1 or PowerShell 7. Some checks (Code Integrity event log, CiTool)
    give more detail when run as Administrator. No check can prove a file is safe; a clean result
    means none of these checks found a problem.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,
    [string]$ExpectedSha256,
    [string]$ExpectedPublisher,
    [switch]$SkipDefenderScan,
    [switch]$SkipRevocationCheck,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ helpers
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [ValidateSet('PASS', 'INFO', 'WARN', 'FAIL')][string]$Level,
        [string]$Area,
        [string]$Message
    )
    $script:Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Message = $Message })
    $color = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red' }[$Level]
    Write-Host ("  [{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Get-NormalizedName([string]$Name) {
    if (-not $Name) { return '' }
    $n = $Name -replace '(?i)\b(inc|llc|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|bv|plc|pty|srl|oy|ab)\b\.?', ''
    return ($n -replace '[^\p{L}\p{N}]', '').ToLowerInvariant()
}

# Reads the embedded Authenticode PKCS#7 blob straight from the PE file and reports
# what it contains: timestamps (RFC 3161 or legacy), nested signatures and how many
# certificates were embedded. This works even when Windows rejects the chain, in which
# case Get-AuthenticodeSignature does not report a TimeStamperCertificate.
function Get-EmbeddedSignatureInfo([string]$LiteralPath) {
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
    $fs = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        if ($fs.Length -lt 64 -or $br.ReadUInt16() -ne 0x5A4D) { return $null }
        $fs.Position = 0x3C; $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or ($peOff + 0x100) -gt $fs.Length) { return $null }
        $fs.Position = $peOff + 24; $magic = $br.ReadUInt16()
        $dataDirOff = if ($magic -eq 0x20B) { $peOff + 24 + 112 } else { $peOff + 24 + 96 }
        $fs.Position = $dataDirOff + 4 * 8                  # entry 4 = certificate table
        $certOff = $br.ReadUInt32(); $certSize = $br.ReadUInt32()
        if ($certOff -eq 0 -or $certSize -lt 8 -or ($certOff + $certSize) -gt $fs.Length) { return $null }
        $fs.Position = $certOff                              # WIN_CERTIFICATE header
        $len = $br.ReadUInt32(); [void]$br.ReadUInt16(); $type = $br.ReadUInt16()
        if ($type -ne 2 -or $len -le 8 -or $len -gt $certSize) { return $null }   # 2 = PKCS#7
        $blob = $br.ReadBytes([int]$len - 8)
    } finally { $fs.Dispose() }

    $cms = New-Object Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($blob)
    $si = $cms.SignerInfos[0]
    $info = [ordered]@{
        Rfc3161 = $false; Legacy = $false; TsaSubject = $null; SigningTime = $null
        NestedSignatures = 0; EmbeddedCertCount = $cms.Certificates.Count
        DigestAlgorithm = $si.DigestAlgorithm.FriendlyName
    }
    foreach ($a in $si.UnsignedAttributes) {
        switch ($a.Oid.Value) {
            '1.3.6.1.4.1.311.3.3.1' {                        # RFC 3161 timestamp token
                $info.Rfc3161 = $true
                $tst = New-Object Security.Cryptography.Pkcs.SignedCms
                $tst.Decode($a.Values[0].RawData)
                $tsi = $tst.SignerInfos[0]
                if ($tsi.Certificate) { $info.TsaSubject = $tsi.Certificate.Subject }
                foreach ($sa in $tsi.SignedAttributes) {
                    if ($sa.Oid.Value -eq '1.2.840.113549.1.9.5') { $info.SigningTime = $sa.Values[0].SigningTime }
                }
            }
            '1.3.6.1.4.1.311.2.4.1' { $info.NestedSignatures += $a.Values.Count }   # dual signing
        }
    }
    foreach ($cs in $si.CounterSignerInfos) {                # legacy Authenticode timestamp
        $info.Legacy = $true
        if (-not $info.TsaSubject -and $cs.Certificate) { $info.TsaSubject = $cs.Certificate.Subject }
        foreach ($sa in $cs.SignedAttributes) {
            if (-not $info.SigningTime -and $sa.Oid.Value -eq '1.2.840.113549.1.9.5') { $info.SigningTime = $sa.Values[0].SigningTime }
        }
    }
    return [pscustomobject]$info
}

$isAdmin =([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------------------------------------------ 1. file
Write-Section 'File'

try {
    $item = Get-Item -LiteralPath $Path -Force
} catch {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 2
}
if ($item.PSIsContainer) {
    Write-Host "$Path is a folder, not a file." -ForegroundColor Red
    exit 2
}
$full = $item.FullName

Add-Finding INFO 'File' "Path: $full"
Add-Finding INFO 'File' ("Size: {0:N0} bytes, last written {1}" -f $item.Length, $item.LastWriteTime)
if (-not $isAdmin) {
    Add-Finding INFO 'File' 'Running without Administrator rights; a few App Control details may be unavailable.'
}

$sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
Add-Finding INFO 'File' "SHA-256: $sha256"
if ($ExpectedSha256) {
    if ($sha256 -eq $ExpectedSha256.Trim()) {
        Add-Finding PASS 'File' 'SHA-256 matches the expected hash.'
    } else {
        Add-Finding FAIL 'File' "SHA-256 does NOT match the expected hash ($($ExpectedSha256.Trim())). The file is corrupt or has been altered."
    }
} else {
    Add-Finding INFO 'File' 'No -ExpectedSha256 given. If the vendor publishes a hash, compare it with the one above.'
}
Add-Finding INFO 'File' "Look up the hash (no upload): https://www.virustotal.com/gui/file/$sha256"

# --- deceptive names
$name = $item.Name
if ($name -match '[‪-‮⁦-⁩‎‏]') {
    Add-Finding FAIL 'File' 'File name contains hidden Unicode direction characters, a trick used to disguise the real extension.'
}
if ($name -match '(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp[34]|zip|rar)\.(exe|scr|com|bat|cmd|msi|pif|js|vbs|ps1|lnk)$') {
    Add-Finding FAIL 'File' "File name has a double extension ($name), a common way to disguise a program as a document."
}
if ($item.Attributes -band [IO.FileAttributes]::Hidden -or $item.Attributes -band [IO.FileAttributes]::System) {
    Add-Finding WARN 'File' "File has Hidden/System attributes: $($item.Attributes)"
}

# --- PE header
$pe = $null
try {
    $fs = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $br = New-Object IO.BinaryReader($fs)
        if ($fs.Length -ge 64 -and $br.ReadUInt16() -eq 0x5A4D) {
            $fs.Position = 0x3C
            $peOff = $br.ReadInt32()
            if ($peOff -gt 0 -and ($peOff + 0x78) -lt $fs.Length) {
                $fs.Position = $peOff
                if ($br.ReadUInt32() -eq 0x00004550) {
                    $machine = $br.ReadUInt16()
                    $fs.Position = $peOff + 22
                    $characteristics = $br.ReadUInt16()
                    $optOff = $peOff + 24
                    $fs.Position = $optOff
                    $magic = $br.ReadUInt16()
                    $fs.Position = $optOff + 68
                    $subsystem = $br.ReadUInt16()
                    $dllChars = $br.ReadUInt16()
                    $dataDirOff = if ($magic -eq 0x20B) { $optOff + 112 } else { $optOff + 96 }
                    $clrSize = 0
                    if (($dataDirOff + 14 * 8 + 8) -le $fs.Length) {
                        $fs.Position = $dataDirOff + 14 * 8 + 4
                        $clrSize = $br.ReadUInt32()
                    }
                    $pe = [pscustomobject]@{
                        Machine = $machine; IsDll = [bool]($characteristics -band 0x2000)
                        Magic = $magic; Subsystem = $subsystem; DllCharacteristics = $dllChars
                        IsDotNet = ($clrSize -gt 0)
                    }
                }
            }
        }
    } finally { $fs.Dispose() }
} catch {
    Add-Finding WARN 'File' "Could not read the file header: $($_.Exception.Message)"
}

$ext = $item.Extension.ToLowerInvariant()
if ($pe) {
    $arch = switch ($pe.Machine) { 0x14C { 'x86 (32-bit)' } 0x8664 { 'x64' } 0xAA64 { 'ARM64' } 0x1C4 { 'ARM' } default { ('0x{0:X4}' -f $pe.Machine) } }
    $sub = switch ($pe.Subsystem) { 2 { 'GUI' } 3 { 'Console' } 1 { 'Native/driver' } 10 { 'EFI' } default { "$($pe.Subsystem)" } }
    $kind = if ($pe.IsDll) { 'DLL' } else { 'Program' }
    $dotnet = if ($pe.IsDotNet) { ', .NET assembly' } else { '' }
    Add-Finding INFO 'File' "Windows PE file: $kind, $arch, $sub subsystem$dotnet"
    if ($ext -notin '.exe', '.dll', '.sys', '.scr', '.com', '.cpl', '.ocx', '.efi', '.msi', '.mui') {
        Add-Finding WARN 'File' "File is a Windows executable but has the extension '$ext'."
    }
    $missing = @()
    if (-not ($pe.DllCharacteristics -band 0x0040)) { $missing += 'ASLR' }
    if (-not ($pe.DllCharacteristics -band 0x0100)) { $missing += 'DEP/NX' }
    if ($missing) {
        Add-Finding INFO 'File' "Built without exploit mitigations: $($missing -join ', ') (common in old or hand-made tools)."
    }
} elseif ($ext -eq '.msi') {
    Add-Finding INFO 'File' 'Windows Installer package (.msi).'
} else {
    Add-Finding WARN 'File' 'File is not a Windows PE executable (no MZ/PE header).'
}

# --- version info
try {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
    $viText = @()
    foreach ($p in 'CompanyName', 'ProductName', 'FileDescription', 'FileVersion', 'OriginalFilename') {
        if ($vi.$p) { $viText += "$p='$($vi.$p.Trim())'" }
    }
    if ($viText) { Add-Finding INFO 'File' ("Version info: " + ($viText -join '; ')) }
    else { Add-Finding INFO 'File' 'No version information embedded.' }
} catch { $vi = $null }

# --- Mark of the Web and other data streams
$zone = $null
try { $zone = Get-Content -LiteralPath $full -Stream 'Zone.Identifier' -ErrorAction Stop } catch { }
if ($zone) {
    $zoneId = ($zone | Where-Object { $_ -match '^ZoneId=' }) -replace '^ZoneId=', ''
    $zoneName = switch ($zoneId) { '0' { 'Local machine' } '1' { 'Intranet' } '2' { 'Trusted sites' } '3' { 'Internet' } '4' { 'Restricted sites' } default { "Zone $zoneId" } }
    Add-Finding INFO 'File' "Mark of the Web present: $zoneName. SmartScreen and Smart App Control will check it at launch."
    foreach ($key in 'HostUrl', 'ReferrerUrl') {
        $line = $zone | Where-Object { $_ -match "^$key=" }
        if ($line) { Add-Finding INFO 'File' ("{0}: {1}" -f $key, ($line -replace "^$key=", '')) }
    }
    if ($zoneId -eq '4') { Add-Finding WARN 'File' 'File came from a Restricted-sites zone.' }
} else {
    Add-Finding WARN 'File' 'No Mark of the Web. SmartScreen and Smart App Control will not get a chance to check it. (Some unzip tools and copies strip it.)'
}
try {
    $streams = Get-Item -LiteralPath $full -Stream * -ErrorAction Stop |
        Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen' }
    foreach ($s in $streams) {
        Add-Finding WARN 'File' ("Extra hidden data stream '{0}' ({1:N0} bytes)." -f $s.Stream, $s.Length)
    }
} catch { }

# ------------------------------------------------------------------ 2. signature
Write-Section 'Digital signature'

$sig = Get-AuthenticodeSignature -LiteralPath $full
$cert = $sig.SignerCertificate
$signerName = $null
$sigValid = ($sig.Status -eq 'Valid')

switch ($sig.Status.ToString()) {
    'Valid'        { Add-Finding PASS 'Signature' 'Signature is valid and the file has not been changed since it was signed.' }
    'NotSigned'    { Add-Finding WARN 'Signature' 'File is NOT signed. You cannot verify who made it. Only run it if you trust the source and the hash matches.' }
    'HashMismatch' { Add-Finding FAIL 'Signature' 'Signature is BROKEN: the file was modified after it was signed.' }
    'NotTrusted'   { Add-Finding FAIL 'Signature' "Signature is not trusted: $($sig.StatusMessage)" }
    'NotSupportedFileFormat' { Add-Finding WARN 'Signature' 'This file type cannot carry an Authenticode signature.' }
    default        { Add-Finding FAIL 'Signature' "Signature problem ($($sig.Status)): $($sig.StatusMessage)" }
}

if ($sig.PSObject.Properties['SignatureType'] -and $cert) {
    Add-Finding INFO 'Signature' "Signature type: $($sig.SignatureType)$(if ($sig.SignatureType -eq 'Catalog') { ' (signed through a Windows catalog file)' })"
}
if ($sig.PSObject.Properties['IsOSBinary'] -and $sig.IsOSBinary) {
    Add-Finding INFO 'Signature' 'File is a Windows operating-system binary.'
}

if ($cert) {
    $signerName = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $issuerName = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    Add-Finding INFO 'Signature' "Signed by: $signerName"
    Add-Finding INFO 'Signature' "Subject:   $($cert.Subject)"
    Add-Finding INFO 'Signature' "Issued by: $issuerName"
    Add-Finding INFO 'Signature' ("Certificate valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}, thumbprint {2}" -f $cert.NotBefore, $cert.NotAfter, $cert.Thumbprint)

    $ageDays = ((Get-Date) - $cert.NotBefore).TotalDays
    if ($ageDays -lt 30) {
        Add-Finding WARN 'Signature' ("Signing certificate was issued only {0:N0} days ago. New certificates are sometimes bought for malware campaigns." -f $ageDays)
    }

    # EV code signing certificate (policy OID 2.23.140.1.3)
    $policyExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.32' }
    if ($policyExt -and $policyExt.Format($false) -match '2\.23\.140\.1\.3') {
        Add-Finding PASS 'Signature' 'Extended Validation (EV) code-signing certificate: the publisher identity was strictly verified.'
    }

    # Timestamp: Windows' view first, then the raw signature blob (embedded signatures only)
    $embedded = $null
    if (-not $sig.PSObject.Properties['SignatureType'] -or $sig.SignatureType -ne 'Catalog') {
        try { $embedded = Get-EmbeddedSignatureInfo $full } catch {
            Add-Finding INFO 'Signature' "Could not parse the embedded signature: $($_.Exception.Message)"
        }
    }
    $hasTimestamp = [bool]$sig.TimeStamperCertificate -or ($embedded -and ($embedded.Rfc3161 -or $embedded.Legacy))
    if ($hasTimestamp) {
        $tsaName = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.GetNameInfo('SimpleName', $false) }
                   elseif ($embedded.TsaSubject) { ($embedded.TsaSubject -split ',')[0] -replace '^CN=', '' }
                   else { 'an unnamed timestamp authority' }
        $kindText = if ($embedded -and $embedded.Rfc3161) { 'an RFC 3161 timestamp' } elseif ($embedded -and $embedded.Legacy) { 'a legacy Authenticode timestamp' } else { 'a timestamp' }
        $whenText = if ($embedded -and $embedded.SigningTime) { (" at {0:yyyy-MM-dd HH:mm} UTC" -f $embedded.SigningTime.ToUniversalTime()) } else { '' }
        Add-Finding PASS 'Signature' "Signature has $kindText from $tsaName$whenText, so it stays valid after the certificate expires."
        if (-not $sig.TimeStamperCertificate) {
            Add-Finding INFO 'Signature' 'Windows did not report this timestamp because the signature failed validation; it was read directly from the file.'
        }
    } else {
        $how = if ($embedded) { ' The signature block contains no RFC 3161 or legacy timestamp, so the signing tool did not add one (for signtool, check that /tr <TSA url> /td sha256 was used and succeeded).' } else { '' }
        Add-Finding WARN 'Signature' "Signature has no timestamp; it stops being valid when the certificate expires.$how"
        if ($cert.NotAfter -lt (Get-Date)) {
            Add-Finding FAIL 'Signature' 'Certificate has expired and there is no timestamp.'
        }
    }
    if ($embedded) {
        Add-Finding INFO 'Signature' ("Embedded signature: {0} digest, {1} certificate(s) included, {2} nested signature(s)." -f $embedded.DigestAlgorithm, $embedded.EmbeddedCertCount, $embedded.NestedSignatures)
    }

    # Chain + revocation
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = if ($SkipRevocationCheck) { 'NoCheck' } else { 'Online' }
    $chain.ChainPolicy.RevocationFlag = 'EntireChain'
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
    [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.3'))
    if ($hasTimestamp) {
        $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
    }
    $chainOk = $chain.Build($cert)
    $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() } | Select-Object -Unique)
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    if ($chain.ChainElements.Count -gt 1) {
        Add-Finding INFO 'Signature' "Root certificate: $($root.GetNameInfo('SimpleName', $false))"
    } else {
        Add-Finding INFO 'Signature' "Issuer certificate '$issuerName' is not installed on this PC, so the chain stops at the signer."
    }
    if ($statuses -contains 'OfflineRevocation') { $statuses = @($statuses | Where-Object { $_ -ne 'RevocationStatusUnknown' }) }

    if ($statuses -contains 'Revoked') {
        Add-Finding FAIL 'Signature' 'The signing certificate (or one above it) has been REVOKED. Do not run this file.'
    } elseif ($chainOk) {
        if ($SkipRevocationCheck) {
            Add-Finding PASS 'Signature' 'Certificate chain is trusted (revocation not checked).'
        } else {
            Add-Finding PASS 'Signature' 'Certificate chain is trusted and not revoked.'
        }
    } else {
        foreach ($s in $statuses) {
            switch ($s) {
                { $_ -in 'RevocationStatusUnknown', 'OfflineRevocation' } {
                    Add-Finding WARN 'Signature' 'Could not reach the certificate authority to check revocation.'
                }
                'NotValidForUsage' { Add-Finding FAIL 'Signature' 'Certificate is not issued for code signing.' }
                'UntrustedRoot'    { Add-Finding FAIL 'Signature' 'Certificate chains to a root that this PC does not trust (possibly self-signed).' }
                'PartialChain'     { Add-Finding FAIL 'Signature' 'Certificate chain is incomplete.' }
                'NotTimeValid'     { Add-Finding WARN 'Signature' 'A certificate in the chain is outside its validity period.' }
                default            { Add-Finding WARN 'Signature' "Chain status: $s" }
            }
        }
    }
    $chain.Dispose()

    # Signer vs. publisher
    if ($ExpectedPublisher) {
        if ($signerName -like "*$ExpectedPublisher*" -or $cert.Subject -like "*$ExpectedPublisher*") {
            Add-Finding PASS 'Signature' "Signer matches the expected publisher '$ExpectedPublisher'."
        } else {
            Add-Finding FAIL 'Signature' "Signer '$signerName' does NOT match the expected publisher '$ExpectedPublisher'."
        }
    }
    if ($vi -and $vi.CompanyName) {
        $a = Get-NormalizedName $signerName
        $b = Get-NormalizedName $vi.CompanyName
        if ($a -and $b -and -not ($a.Contains($b) -or $b.Contains($a))) {
            Add-Finding WARN 'Signature' "Signer '$signerName' differs from the CompanyName in the file '$($vi.CompanyName.Trim())'. Check this is expected."
        }
    }
} elseif (-not $ExpectedPublisher) {
    # nothing else to report
} else {
    Add-Finding FAIL 'Signature' "Expected publisher '$ExpectedPublisher' but the file is not signed."
}

# ------------------------------------------------------------------ 3. Defender
Write-Section 'Microsoft Defender'

if ($SkipDefenderScan) {
    Add-Finding INFO 'Antivirus' 'Defender scan skipped (-SkipDefenderScan).'
} else {
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($mpStatus.AMRunningMode -and $mpStatus.AMRunningMode -ne 'Normal') {
            Add-Finding INFO 'Antivirus' "Defender running mode: $($mpStatus.AMRunningMode) (another antivirus may be primary)."
        }
        if (-not $mpStatus.RealTimeProtectionEnabled) {
            Add-Finding WARN 'Antivirus' 'Defender real-time protection is OFF.'
        }
        $sigAge = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalDays
        if ($sigAge -gt 7) {
            Add-Finding WARN 'Antivirus' ("Defender definitions are {0:N0} days old. Update them first: Update-MpSignature" -f $sigAge)
        }
    } catch {
        Add-Finding INFO 'Antivirus' 'Could not read Defender status (another antivirus may be installed).'
    }

    $mpCandidates = @()
    $platformDir = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path $platformDir) {
        $mpCandidates += Get-ChildItem $platformDir -Directory |
            Sort-Object { try { [version](($_.Name -split '-')[0]) } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' }
    }
    $mpCandidates += Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    $mpCmd = $mpCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($mpCmd) {
        Write-Host '  Scanning with Defender...' -ForegroundColor DarkGray
        $scanOut = & $mpCmd -Scan -ScanType 3 -File $full -DisableRemediation 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            Add-Finding PASS 'Antivirus' 'Defender found no threats in the file.'
        } elseif ($code -eq 2) {
            $threats = ($scanOut | Where-Object { $_ -match 'Threat|Resources' }) -join ' | '
            Add-Finding FAIL 'Antivirus' "Defender DETECTED A THREAT. $threats"
        } else {
            Add-Finding WARN 'Antivirus' "Defender scan did not complete (exit code $code): $((($scanOut | Select-Object -Last 2) -join ' ').Trim())"
        }
    } else {
        Add-Finding WARN 'Antivirus' 'MpCmdRun.exe not found; scan the file with your installed antivirus.'
    }
}

# ------------------------------------------------------------------ 4. App Control
Write-Section 'App Control for Business (WDAC), Smart App Control, AppLocker'

$umci = $null
$stateNames = @{ 0 = 'Off'; 1 = 'Audit mode'; 2 = 'Enforced' }
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $kmci = [int]$dg.CodeIntegrityPolicyEnforcementStatus
    $umci = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    Add-Finding INFO 'AppControl' "Kernel-mode code integrity policy: $($stateNames[$kmci])"
    Add-Finding INFO 'AppControl' "User-mode code integrity (decides whether .exe files may run): $($stateNames[$umci])"
} catch {
    Add-Finding WARN 'AppControl' "Could not query Device Guard status: $($_.Exception.Message)"
}

# Active policies (Windows 11 22H2+)
$citool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
if (Test-Path $citool) {
    try {
        $raw = (& $citool --list-policies --json 2>$null) -join "`n"
        $start = $raw.IndexOf('{'); $end = $raw.LastIndexOf('}')
        if ($start -ge 0 -and $end -gt $start) {
            $policies = @(($raw.Substring($start, $end - $start + 1) | ConvertFrom-Json).Policies)
            $enforced = @($policies | Where-Object { $_.IsEnforced })
            Add-Finding INFO 'AppControl' "Active code integrity policies: $($enforced.Count)"
            foreach ($p in $enforced) {
                $kindText = if ($p.IsSystemPolicy) { 'Windows' } else { 'custom' }
                Add-Finding INFO 'AppControl' ("  - {0} ({1}, {2})" -f $p.FriendlyName, $kindText, $p.PolicyID)
            }
        } else {
            Add-Finding INFO 'AppControl' 'CiTool returned no policy list (may need Administrator).'
        }
    } catch {
        Add-Finding INFO 'AppControl' "Could not list policies with CiTool: $($_.Exception.Message)"
    }
}

# Prediction for WDAC
switch ($umci) {
    2 {
        if (-not $sigValid) {
            Add-Finding WARN 'AppControl' 'BLOCK EXPECTED: user-mode App Control is enforced and the file is not validly signed. It will run only if a policy allows its hash.'
        } else {
            Add-Finding WARN 'AppControl' "User-mode App Control is ENFORCED. The file runs only if a policy trusts '$signerName' (or its hash, or a managed installer). Ask your administrator or check the Code Integrity log after a launch attempt."
        }
    }
    1 { Add-Finding INFO 'AppControl' 'App Control is in audit mode: it will not block, but logs event 3076 if the file would have been blocked.' }
    0 { Add-Finding PASS 'AppControl' 'No enforced user-mode App Control policy: WDAC will not block this file.' }
}

# Smart App Control
$sacState = $null
try {
    $sacState = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop).VerifiedAndReputablePolicyState
} catch { }
switch ($sacState) {
    1 {
        Add-Finding INFO 'AppControl' 'Smart App Control: ON'
        if (-not $sigValid) {
            Add-Finding WARN 'AppControl' 'BLOCK LIKELY: Smart App Control blocks unsigned or invalidly signed apps unless Microsoft''s cloud already knows them as safe.'
        } else {
            Add-Finding PASS 'AppControl' 'Smart App Control generally allows apps with a valid signature from a trusted certificate authority (cloud reputation is checked at launch).'
        }
    }
    2 { Add-Finding INFO 'AppControl' 'Smart App Control: Evaluation mode (not blocking yet).' }
    0 { Add-Finding INFO 'AppControl' 'Smart App Control: Off.' }
    default { Add-Finding INFO 'AppControl' 'Smart App Control: not available on this system.' }
}

# Past Code Integrity events for this file
try {
    $since = (Get-Date).AddDays(-30)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033, 3034, 3076, 3077; StartTime = $since
    } -MaxEvents 5000 -ErrorAction Stop | Where-Object { $_.Message -like "*$name*" }
    if ($events) {
        foreach ($e in ($events | Select-Object -First 5)) {
            $what = switch ($e.Id) { 3077 { 'BLOCKED by App Control' } 3076 { 'would be blocked (audit)' } 3033 { 'blocked: signing level not met' } 3034 { 'would be blocked: signing level (audit)' } }
            Add-Finding WARN 'AppControl' ("{0:yyyy-MM-dd HH:mm} event {1}: {2}" -f $e.TimeCreated, $e.Id, $what)
        }
    } else {
        Add-Finding INFO 'AppControl' 'No Code Integrity block or audit events for this file name in the last 30 days.'
    }
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Add-Finding INFO 'AppControl' 'No Code Integrity block or audit events in the last 30 days.'
    } else {
        Add-Finding INFO 'AppControl' 'Could not read the Code Integrity event log (run as Administrator for this check).'
    }
}

# AppLocker
try {
    Import-Module AppLocker -ErrorAction Stop -WarningAction SilentlyContinue
    $xmlText = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
    $xml = [xml]$xmlText
    $exeRules = $xml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -in 'Exe', 'Msi', 'Dll' -and $_.HasChildNodes }
    if (-not $exeRules) {
        Add-Finding PASS 'AppControl' 'AppLocker: no executable rules configured, so AppLocker will not block this file.'
    } else {
        $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("applocker-{0}.xml" -f [guid]::NewGuid())
        try {
            Set-Content -LiteralPath $tmp -Value $xmlText -Encoding UTF8
            $user = "$env:USERDOMAIN\$env:USERNAME"
            $result = Test-AppLockerPolicy -XmlPolicy $tmp -Path $full -User $user -ErrorAction Stop
            $decision = "$($result.PolicyDecision)"
            $modes = ($exeRules | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)" }) -join ', '
            Add-Finding INFO 'AppControl' "AppLocker rule collections: $modes; Application Identity service: $(if ($svc) { $svc.Status } else { 'not found' })"
            if ($decision -match 'Denied') {
                Add-Finding WARN 'AppControl' "AppLocker decision for ${user}: $decision$(if ($result.MatchingRule) { " (rule: $($result.MatchingRule))" }). The file will be blocked if the collection is enforced."
            } else {
                Add-Finding PASS 'AppControl' "AppLocker decision for ${user}: $decision"
            }
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
} catch {
    if ($_.Exception.Message -match 'AppLocker.*not loaded|no valid module') {
        Add-Finding INFO 'AppControl' 'AppLocker: not available on this Windows edition, so it cannot block this file.'
    } else {
        Add-Finding INFO 'AppControl' "AppLocker could not be evaluated: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------ 4b. "Blocked by group policy"
# Windows error 1260 (ERROR_ACCESS_DISABLED_BY_POLICY) comes from AppLocker or Software Restriction Policies.
Write-Section 'Group Policy blocks (Software Restriction Policies, AppLocker events, Explorer lists)'

$gpHint = 'Ask IT: "gpresult /h gp.html" (as Administrator) names the Group Policy Object that sets the rule.'

# Software Restriction Policies: ask Windows which SRP level it would give this file, without running it.
try {
    if (-not ('SaferApi' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class SaferApi {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct SAFER_CODE_PROPERTIES {
    public uint cbSize; public uint dwCheckFlags; public string ImagePath; public IntPtr hImageFileHandle;
    public uint UrlZoneId; [MarshalAs(UnmanagedType.ByValArray, SizeConst=64)] public byte[] ImageHash;
    public uint dwImageHashSize; public long ImageSize; public uint HashAlgorithm; public IntPtr pByteBlock;
    public IntPtr hWndParent; public uint dwWVTUIChoice; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SaferIdentifyLevel(uint n, ref SAFER_CODE_PROPERTIES p, out IntPtr h, IntPtr r);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SaferGetLevelInformation(IntPtr h, int cls, out uint v, uint cb, out uint ret);
  [DllImport("advapi32.dll")] static extern bool SaferCloseLevel(IntPtr h);
  public static uint GetLevel(string path) {
    var p = new SAFER_CODE_PROPERTIES(); p.cbSize = (uint)Marshal.SizeOf(p);
    p.dwCheckFlags = 1 | 4 | 8;   // path, hash and certificate rules
    p.ImagePath = path; p.ImageHash = new byte[64]; p.dwWVTUIChoice = 2;   // no UI
    IntPtr h;
    if (!SaferIdentifyLevel(1, ref p, out h, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception();
    try { uint v, r; if (!SaferGetLevelInformation(h, 1, out v, 4, out r)) throw new System.ComponentModel.Win32Exception(); return v; }
    finally { SaferCloseLevel(h); } } }
'@
    }
    $srpLevel = [SaferApi]::GetLevel($full)
    $srpNames = @{ 0x0 = 'Disallowed'; 0x1000 = 'Constrained'; 0x10000 = 'Untrusted'; 0x20000 = 'Basic User'; 0x40000 = 'Unrestricted' }
    $srpName = if ($srpNames.ContainsKey([int]$srpLevel)) { $srpNames[[int]$srpLevel] } else { 'Unknown' }
    $srpText = 'Software Restriction Policies level: {0} (0x{1:X})' -f $srpName, $srpLevel
    if ($exeRules) {
        # When an AppLocker policy has rules, Windows ignores SRP.
        Add-Finding INFO 'GroupPolicy' "$srpText. Not applied: AppLocker rules exist, and Windows then ignores SRP."
    } elseif ($srpLevel -eq 0x40000) {
        Add-Finding PASS 'GroupPolicy' "$srpText. SRP will not block this file."
    } elseif ($srpLevel -le 0x10000) {
        Add-Finding FAIL 'GroupPolicy' "$srpText. BLOCK EXPECTED: Windows will say ""This program is blocked by group policy"". $gpHint"
    } else {
        Add-Finding WARN 'GroupPolicy' "$srpText. The file will run, but without administrator rights, so an installer may fail. $gpHint"
    }
} catch {
    Add-Finding INFO 'GroupPolicy' "Software Restriction Policies could not be evaluated: $($_.Exception.Message)"
}

# AppLocker evidence: did an earlier attempt to run this file get blocked (8004/8007) or audited (8003/8006)?
$alLogs = @{ 'Microsoft-Windows-AppLocker/EXE and DLL' = 8003, 8004; 'Microsoft-Windows-AppLocker/MSI and Script' = 8006, 8007 }
$alFound = $false; $alReadable = $false
foreach ($log in $alLogs.Keys) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $alLogs[$log]; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 5000 -ErrorAction Stop |
            Where-Object { $_.Message -like "*$name*" }
        $alReadable = $true
        foreach ($e in ($evts | Select-Object -First 5)) {
            $alFound = $true
            $what = if ($e.Id -in 8004, 8007) { 'BLOCKED by AppLocker' } else { 'would be blocked by AppLocker (audit only)' }
            Add-Finding WARN 'GroupPolicy' ("{0:yyyy-MM-dd HH:mm} AppLocker event {1}: {2}. The event names the rule collection; send it to IT." -f $e.TimeCreated, $e.Id, $what)
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') { $alReadable = $true }
    }
}
if (-not $alFound) {
    if ($alReadable) { Add-Finding INFO 'GroupPolicy' 'No AppLocker block or audit events for this file name in the last 30 days.' }
    else { Add-Finding INFO 'GroupPolicy' 'AppLocker event logs are not available on this system.' }
}

# Explorer "Don't run specified Windows applications" / "Run only specified Windows applications".
# These match on the file name only and only apply when the program is started from Explorer.
$explorerListSet = $false
foreach ($hive in 'HKCU', 'HKLM') {
    $base = "${hive}:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $props = Get-ItemProperty -Path $base -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    if ($props.DisallowRun -eq 1 -or $props.RestrictRun -eq 1) { $explorerListSet = $true }
    if ($props.DisallowRun -eq 1) {
        $list = @((Get-ItemProperty -Path "$base\DisallowRun" -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Value)" })
        if ($list -contains $name) {
            Add-Finding FAIL 'GroupPolicy' "BLOCK EXPECTED: '$name' is on the ""Don't run specified Windows applications"" list ($hive). Explorer will refuse to start it. $gpHint"
        } else {
            Add-Finding INFO 'GroupPolicy' "Explorer DisallowRun list is active ($hive, $($list.Count) names); this file name is not on it."
        }
    }
    if ($props.RestrictRun -eq 1) {
        $list = @((Get-ItemProperty -Path "$base\RestrictRun" -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Value)" })
        if ($list -contains $name) {
            Add-Finding PASS 'GroupPolicy' "'$name' is on the ""Run only specified Windows applications"" list ($hive)."
        } else {
            Add-Finding FAIL 'GroupPolicy' "BLOCK EXPECTED: only listed applications may run from Explorer ($hive), and '$name' is not on the list. $gpHint"
        }
    }
}
if (-not $explorerListSet) {
    Add-Finding PASS 'GroupPolicy' 'No Explorer "Don''t run" or "Run only" application lists are set.'
}

# ------------------------------------------------------------------ 5. permissions
Write-Section 'File permissions'

$broadSids = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-32-545' = 'Users'
    'S-1-5-4'      = 'INTERACTIVE'
    'S-1-5-32-546' = 'Guests'
    'S-1-5-7'      = 'ANONYMOUS LOGON'
    'S-1-5-2'      = 'NETWORK'
}
$R = [Security.AccessControl.FileSystemRights]
$fileWriteMask = [int]($R::WriteData -bor $R::AppendData -bor $R::Delete -bor $R::ChangePermissions -bor $R::TakeOwnership)
$dirWriteMask  = [int]($R::CreateFiles -bor $R::CreateDirectories -bor $R::ChangePermissions -bor $R::TakeOwnership)
$GENERIC_ALL = 0x10000000; $GENERIC_WRITE = 0x40000000

function Get-AclRules([string]$LiteralPath) {
    $acl = Get-Acl -LiteralPath $LiteralPath
    return [pscustomobject]@{
        Acl   = $acl
        Rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    }
}
function Resolve-SidName([string]$Sid) {
    try { return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

try {
    $fileAcl = Get-AclRules $full
    Add-Finding INFO 'Permissions' "Owner: $($fileAcl.Acl.Owner)"
    foreach ($r in $fileAcl.Rules) {
        $inh = if ($r.IsInherited) { 'inherited' } else { 'explicit' }
        Add-Finding INFO 'Permissions' ("  {0,-5} {1}: {2} ({3})" -f $r.AccessControlType, (Resolve-SidName $r.IdentityReference.Value), $r.FileSystemRights, $inh)
    }

    # Effective execute for current user (approximation from ACL and token groups)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $mySids = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
    $allow = 0; $deny = 0
    foreach ($r in $fileAcl.Rules) {
        if ($mySids -contains $r.IdentityReference.Value) {
            $bits = [int]$r.FileSystemRights
            if ($bits -band $GENERIC_ALL) { $bits = $bits -bor [int]([Security.AccessControl.FileSystemRights]::FullControl) }
            if ($r.AccessControlType -eq 'Allow') { $allow = $allow -bor $bits } else { $deny = $deny -bor $bits }
        }
    }
    $execBit = [int]([Security.AccessControl.FileSystemRights]::ExecuteFile)
    if ($deny -band $execBit) {
        Add-Finding WARN 'Permissions' 'Execute permission is explicitly DENIED for you; the file will not start.'
    } elseif ($allow -band $execBit) {
        Add-Finding PASS 'Permissions' "You ($($me.Name)) have Read & Execute permission on the file."
    } else {
        Add-Finding WARN 'Permissions' 'No Execute permission is granted to you on this file; Windows will refuse to start it.'
    }

    # Broad groups that can modify the file
    foreach ($r in $fileAcl.Rules) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -eq 'Allow' -and $broadSids.ContainsKey($sid)) {
            $bits = [int]$r.FileSystemRights
            if (($bits -band $fileWriteMask) -or ($bits -band ($GENERIC_ALL -bor $GENERIC_WRITE))) {
                Add-Finding WARN 'Permissions' "'$($broadSids[$sid])' can modify or replace this file ($($r.FileSystemRights)). Another user or process could swap it after you check it."
            }
        }
    }

    # Parent folder: DLL planting risk
    $parent = $item.DirectoryName
    $dirAcl = Get-AclRules $parent
    $dirWritable = $false
    foreach ($r in $dirAcl.Rules) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -eq 'Allow' -and $broadSids.ContainsKey($sid)) {
            $bits = [int]$r.FileSystemRights
            if (($bits -band $dirWriteMask) -or ($bits -band ($GENERIC_ALL -bor $GENERIC_WRITE))) {
                $dirWritable = $true
                Add-Finding WARN 'Permissions' "Folder '$parent' is writable by '$($broadSids[$sid])'. Other users could plant DLLs that this program loads."
            }
        }
    }
    if (-not $dirWritable) {
        Add-Finding PASS 'Permissions' 'Containing folder is not writable by broad groups (Everyone/Users).'
    }

    $dlls = @(Get-ChildItem -LiteralPath $parent -Filter '*.dll' -File -ErrorAction SilentlyContinue)
    $protectedRoots = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    $inProtected = [bool]($protectedRoots | Where-Object { $parent.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })
    if ($dlls.Count -gt 0 -and $pe -and -not $pe.IsDll -and -not $inProtected) {
        $list = ($dlls | Select-Object -First 5 | ForEach-Object Name) -join ', '
        Add-Finding WARN 'Permissions' "$($dlls.Count) DLL file(s) sit next to the program ($list). A program can load DLLs from its own folder, so stray downloads here could be side-loaded. Consider moving the program to its own empty folder before running it."
    }
} catch {
    Add-Finding WARN 'Permissions' "Could not read permissions: $($_.Exception.Message)"
}

# ------------------------------------------------------------------ summary
Write-Section 'Summary'
$fails = @($script:Findings | Where-Object Level -eq 'FAIL')
$warns = @($script:Findings | Where-Object Level -eq 'WARN')
$passes = @($script:Findings | Where-Object Level -eq 'PASS')
Write-Host ("  {0} passed, {1} warnings, {2} failures" -f $passes.Count, $warns.Count, $fails.Count)

if ($ReportPath) {
    try {
        if ($ReportPath -match '\.csv$') {
            $script:Findings | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding UTF8
        } else {
            [pscustomobject]@{
                File = $full; Sha256 = $sha256; Checked = (Get-Date).ToString('o')
                Signer = $signerName; SignatureStatus = "$($sig.Status)"; Findings = $script:Findings
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
        }
        Write-Host "  Report saved to $ReportPath" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not save report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
if ($fails.Count -gt 0) {
    Write-Host '  VERDICT: DO NOT RUN. One or more checks failed:' -ForegroundColor Red
    $fails | ForEach-Object { Write-Host "    - $($_.Message)" -ForegroundColor Red }
    $exitCode = 2
} elseif ($warns.Count -gt 0) {
    Write-Host '  VERDICT: REVIEW the warnings above before running.' -ForegroundColor Yellow
    $exitCode = 1
} else {
    Write-Host '  VERDICT: No problems found by these checks.' -ForegroundColor Green
    $exitCode = 0
}
Write-Host '  No automated check can prove a file is safe. Only run software from sources you trust.' -ForegroundColor DarkGray
exit $exitCode
