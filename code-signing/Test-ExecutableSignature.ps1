#Requires -Version 5.1
<#
.SYNOPSIS
    Checks ONLY the code signature and certificate of a Windows executable, and says who must act.

.DESCRIPTION
    Signature problems can only be fixed by the publisher (whoever signs and ships the file).
    This script checks them in isolation and, for every problem, gives the action for:
      - Publisher : what the software publisher must change in how they sign or release the file
      - You       : what the person who downloaded the file should do meanwhile

    The file is never executed. Local safety checks (antivirus, App Control, permissions, Mark of the
    Web) are in Test-ExecutableEnvironment.ps1. Test-ExecutableSafety.ps1 runs everything together.

    Checks:
      - Authenticode status (valid, not signed, tampered, untrusted)
      - Signer, issuer, validity dates, EV certificate, certificate age, Lifetime Signing EKU
      - Digest algorithm (SHA-1 is obsolete)
      - Timestamp (RFC 3161 or legacy), read from Windows and directly from the file
      - Days until the certificate expires when there is no timestamp
      - Certificate chain with online revocation check
      - Certificates embedded in the signature (full chain or signer only)
      - Signer vs. the CompanyName in the file, and an optional expected publisher

    Exit code: 0 = no problems, 1 = warnings, 2 = failures.

.PARAMETER Path
    The file to check (.exe, .dll, .msi, .sys, ...).

.PARAMETER ExpectedPublisher
    Text the signer name must contain, for example "Mozilla Corporation".

.PARAMETER SkipRevocationCheck
    Do not contact the certificate authority to check revocation (offline use).

.PARAMETER ExpiryWarningDays
    For signatures without a timestamp, warn more urgently when the certificate expires within this
    many days. Default 90.

.PARAMETER ReportPath
    Optional path to save the findings and actions as .json or .csv.

.EXAMPLE
    .\Test-ExecutableSignature.ps1 -Path .\setup.exe -ExpectedPublisher "Contoso Ltd"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,
    [string]$ExpectedPublisher,
    [switch]$SkipRevocationCheck,
    [int]$ExpiryWarningDays = 90,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ helpers
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [ValidateSet('PASS', 'INFO', 'WARN', 'FAIL')][string]$Level,
        [string]$Area,
        [string]$Message,
        [System.Collections.IDictionary]$Do      # ordered @{ Publisher = '...'; You = '...' }
    )
    $actions = @()
    if ($Do) { foreach ($k in $Do.Keys) { $actions += [pscustomobject]@{ Owner = $k; Action = $Do[$k] } } }
    $script:Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Message = $Message; Actions = $actions })
    $color = @{ PASS = 'Green'; INFO = 'Gray'; WARN = 'Yellow'; FAIL = 'Red' }[$Level]
    Write-Host ("  [{0}] {1}" -f $Level, $Message) -ForegroundColor $color
    foreach ($a in $actions) { Write-Host ("         -> {0}: {1}" -f $a.Owner, $a.Action) -ForegroundColor DarkCyan }
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

# Reads the embedded Authenticode PKCS#7 blob straight from the PE file: timestamps
# (RFC 3161 or legacy), nested signatures and the number of embedded certificates.
# Works even when Windows rejects the chain (then Get-AuthenticodeSignature reports no timestamp).
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

# ------------------------------------------------------------------ file
Write-Section 'File'
try {
    $item = Get-Item -LiteralPath $Path -Force
} catch {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 2
}
if ($item.PSIsContainer) { Write-Host "$Path is a folder, not a file." -ForegroundColor Red; exit 2 }
$full = $item.FullName
Add-Finding INFO 'File' "Path: $full"
Add-Finding INFO 'File' ("SHA-256: {0}" -f (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash)
$vi = $null
try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($full) } catch { }
if ($vi -and $vi.CompanyName) { Add-Finding INFO 'File' "CompanyName in file: '$($vi.CompanyName.Trim())'" }

# ------------------------------------------------------------------ signature
Write-Section 'Signature'

$sig = Get-AuthenticodeSignature -LiteralPath $full
$cert = $sig.SignerCertificate
$isCatalog = $sig.PSObject.Properties['SignatureType'] -and "$($sig.SignatureType)" -eq 'Catalog'
$signerName = $null

$signHow = 'Sign with a code-signing certificate and a timestamp, e.g. jsign --alg SHA-256 --tsaurl <TSA> --tsmode RFC3161 --certfile <chain> file.exe'
switch ($sig.Status.ToString()) {
    'Valid' {
        Add-Finding PASS 'Signature' 'Signature is valid and the file has not been changed since it was signed.'
    }
    'NotSigned' {
        Add-Finding WARN 'Signature' 'File is NOT signed, so nobody can verify who made it.' ([ordered]@{
            Publisher = $signHow
            You       = 'Ask the publisher for a signed build, or at least compare the SHA-256 above with a hash they publish on an HTTPS page.'
        })
    }
    'HashMismatch' {
        Add-Finding FAIL 'Signature' 'Signature is BROKEN: the file was changed after it was signed.' ([ordered]@{
            You       = 'Delete the file and download it again from the official site. If the new copy also fails, tell the publisher.'
            Publisher = 'If the official download fails this check, the file was altered after signing (build step, CDN or compromise). Investigate, rebuild and re-sign.'
        })
    }
    'NotSupportedFileFormat' {
        Add-Finding INFO 'Signature' 'This file type cannot carry an Authenticode signature.'
    }
    default {
        Add-Finding FAIL 'Signature' "Signature is not trusted ($($sig.Status)): $($sig.StatusMessage)" ([ordered]@{
            You = 'Do not run it until the certificate problems in this report are fixed by the publisher (or IT, for an internal CA).'
        })
    }
}

if ($cert) {
    $signerName = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $issuerName = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    if ($isCatalog) { Add-Finding INFO 'Signature' 'Signed through a Windows catalog file (normal for Windows components).' }
    if ($sig.PSObject.Properties['IsOSBinary'] -and $sig.IsOSBinary) { Add-Finding INFO 'Signature' 'File is a Windows operating-system binary.' }

    Write-Section 'Certificate'
    Add-Finding INFO 'Certificate' "Signed by: $signerName"
    Add-Finding INFO 'Certificate' "Subject:   $($cert.Subject)"
    Add-Finding INFO 'Certificate' "Issued by: $issuerName"
    Add-Finding INFO 'Certificate' ("Valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}, thumbprint {2}" -f $cert.NotBefore, $cert.NotAfter, $cert.Thumbprint)

    $now = Get-Date
    $ageDays = ($now - $cert.NotBefore).TotalDays
    $daysLeft = ($cert.NotAfter - $now).TotalDays
    $selfSigned = ($cert.Subject -eq $cert.Issuer)

    if ($ageDays -lt 30) {
        Add-Finding WARN 'Certificate' ("Certificate was issued only {0:N0} days ago. New certificates are sometimes bought for malware campaigns." -f $ageDays) ([ordered]@{
            You       = 'Take extra care: confirm the hash or the signer with the publisher through a channel you already trust.'
            Publisher = 'Nothing to fix. After a certificate renewal, SmartScreen reputation has to build up again; an EV certificate shortens that.'
        })
    }

    $ekuExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    $ekuText = if ($ekuExt) { $ekuExt.Format($false) } else { '' }
    if ($ekuExt -and $ekuText -notmatch '1\.3\.6\.1\.5\.5\.7\.3\.3') {
        Add-Finding FAIL 'Certificate' "Certificate is not issued for code signing (EKU: $ekuText)." ([ordered]@{
            Publisher = 'Sign with a certificate that has the Code Signing EKU (1.3.6.1.5.5.7.3.3).'
            You       = 'Do not run it; ask the publisher for a correctly signed build.'
        })
    }
    if ($ekuText -match '1\.3\.6\.1\.4\.1\.311\.10\.3\.13') {
        Add-Finding WARN 'Certificate' 'Certificate has the Lifetime Signing EKU: signatures expire with the certificate even when timestamped.' ([ordered]@{
            Publisher = 'Use a code-signing certificate without the Lifetime Signing EKU, or plan to re-sign and re-release before it expires.'
        })
    }

    $policyExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.32' }
    if ($policyExt -and $policyExt.Format($false) -match '2\.23\.140\.1\.3') {
        Add-Finding PASS 'Certificate' 'Extended Validation (EV) code-signing certificate: the publisher identity was strictly verified.'
    }

    # ---------------------------------------------------------- timestamp + embedded data
    Write-Section 'Timestamp'
    $embedded = $null
    if (-not $isCatalog) {
        try { $embedded = Get-EmbeddedSignatureInfo $full } catch {
            Add-Finding INFO 'Timestamp' "Could not parse the embedded signature: $($_.Exception.Message)"
        }
    }
    $hasTimestamp = [bool]$sig.TimeStamperCertificate -or ($embedded -and ($embedded.Rfc3161 -or $embedded.Legacy))

    if ($hasTimestamp) {
        $tsaName = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.GetNameInfo('SimpleName', $false) }
                   elseif ($embedded.TsaSubject) { ($embedded.TsaSubject -split ',')[0] -replace '^CN=', '' }
                   else { 'an unnamed timestamp authority' }
        $kindText = if ($embedded -and $embedded.Rfc3161) { 'an RFC 3161 timestamp' } elseif ($embedded -and $embedded.Legacy) { 'a legacy Authenticode timestamp' } else { 'a timestamp' }
        $whenText = if ($embedded -and $embedded.SigningTime) { (" at {0:yyyy-MM-dd HH:mm} UTC" -f $embedded.SigningTime.ToUniversalTime()) } else { '' }
        Add-Finding PASS 'Timestamp' "Signature has $kindText from $tsaName$whenText, so it stays valid after the certificate expires."
        if (-not $sig.TimeStamperCertificate) {
            Add-Finding INFO 'Timestamp' 'Windows did not report this timestamp because the signature failed validation; it was read directly from the file.'
        }
        if ($embedded -and $embedded.Legacy -and -not $embedded.Rfc3161) {
            Add-Finding INFO 'Timestamp' 'Legacy Authenticode timestamp. It works, but RFC 3161 is the current standard.' ([ordered]@{
                Publisher = 'Optional: switch to RFC 3161 (jsign --tsmode RFC3161, signtool /tr <TSA> /td sha256).'
            })
        }
        if ($daysLeft -lt 0) {
            Add-Finding INFO 'Timestamp' ("Certificate expired on {0:yyyy-MM-dd}; this signature is still valid because of the timestamp." -f $cert.NotAfter) ([ordered]@{
                Publisher = 'Renew the certificate before signing the next release.'
            })
        }
    } else {
        $how = if ($embedded) { ' The signature block contains no RFC 3161 or legacy timestamp, so the signing tool did not add one.' } else { '' }
        if ($daysLeft -lt 0) {
            Add-Finding FAIL 'Timestamp' ("Certificate expired on {0:yyyy-MM-dd} and there is no timestamp: the signature is no longer valid.$how" -f $cert.NotAfter) ([ordered]@{
                Publisher = 'Re-sign the file with a valid certificate AND a timestamp, then release it again. A timestamp cannot be added after expiry.'
                You       = 'Do not run it; ask the publisher for a newly signed build.'
            })
        } else {
            $urgency = if ($daysLeft -le $ExpiryWarningDays) { ' SOON' } else { '' }
            Add-Finding WARN 'Timestamp' ("Signature has no timestamp. It stops being valid when the certificate expires{0} on {1:yyyy-MM-dd} ({2:N0} days).{3}" -f $urgency, $cert.NotAfter, $daysLeft, $how) ([ordered]@{
                Publisher = 'Add a timestamp now without re-signing: jsign timestamp --tsaurl <TSA> --tsmode RFC3161 file.exe (or signtool timestamp /tr <TSA> /td sha256). Add --tsaurl and --tsmode RFC3161 to the signing pipeline.'
                You       = ("It works today. After {0:yyyy-MM-dd}, Smart App Control blocks it and signature checks fail; ask the publisher for a timestamped build." -f $cert.NotAfter)
            })
        }
    }

    if ($embedded) {
        Add-Finding INFO 'Timestamp' ("Embedded signature: {0} digest, {1} certificate(s) included, {2} nested signature(s)." -f $embedded.DigestAlgorithm, $embedded.EmbeddedCertCount, $embedded.NestedSignatures)
        if ($embedded.DigestAlgorithm -match '(?i)sha1' -and $embedded.NestedSignatures -eq 0) {
            Add-Finding WARN 'Timestamp' 'Signature uses only SHA-1, which Windows no longer trusts for new signatures.' ([ordered]@{
                Publisher = 'Sign with SHA-256 (jsign --alg SHA-256, signtool /fd sha256).'
            })
        }
    }

    # ---------------------------------------------------------- chain + revocation
    Write-Section 'Certificate chain'
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = if ($SkipRevocationCheck) { 'NoCheck' } else { 'Online' }
    $chain.ChainPolicy.RevocationFlag = 'EntireChain'
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
    [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.3'))
    if ($hasTimestamp) { $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid' }
    $chainOk = $chain.Build($cert)
    $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() } | Select-Object -Unique)
    if ($statuses -contains 'OfflineRevocation') { $statuses = @($statuses | Where-Object { $_ -ne 'RevocationStatusUnknown' }) }
    # Without a complete, trusted chain, revocation cannot be checked; that is not a separate problem.
    $brokenChain = ($statuses -contains 'PartialChain') -or ($statuses -contains 'UntrustedRoot')
    if ($brokenChain) { $statuses = @($statuses | Where-Object { $_ -notin 'RevocationStatusUnknown', 'OfflineRevocation' }) }

    $names = @($chain.ChainElements | ForEach-Object { $_.Certificate.GetNameInfo('SimpleName', $false) })
    Add-Finding INFO 'Chain' ("Chain: " + ($names -join '  ->  '))

    if ($statuses -contains 'Revoked') {
        Add-Finding FAIL 'Chain' 'The signing certificate (or one above it) has been REVOKED.' ([ordered]@{
            You       = 'Do not run it. Delete the file.'
            Publisher = 'Find out why it was revoked (key compromise?). Get a new certificate, re-sign every supported release with a timestamp, and publish the new builds.'
        })
    } elseif ($chainOk) {
        $msg = if ($SkipRevocationCheck) { 'Certificate chain is trusted (revocation not checked).' } else { 'Certificate chain is trusted and not revoked.' }
        Add-Finding PASS 'Chain' $msg
    } else {
        foreach ($s in $statuses) {
            switch ($s) {
                'UntrustedRoot' {
                    if ($selfSigned) {
                        Add-Finding FAIL 'Chain' 'Certificate is self-signed: anyone can create one with any name.' ([ordered]@{
                            Publisher = 'Sign with a certificate from a public code-signing CA (OV or EV).'
                            You       = 'Do not run it, and do not install the certificate to make the warning go away.'
                        })
                    } else {
                        Add-Finding FAIL 'Chain' "Certificate chains to a root this PC does not trust ($($names[-1]))." ([ordered]@{
                            Publisher = 'For external users, sign with a certificate from a public code-signing CA. For company PCs only, have IT deploy the root CA to those PCs (Group Policy or Intune).'
                            You       = 'Do not install an unknown root certificate yourself; a root is trusted for everything on the PC. Ask the publisher or your IT department.'
                        })
                    }
                }
                'PartialChain' {
                    Add-Finding FAIL 'Chain' "Certificate chain is incomplete: the issuer '$issuerName' is not on this PC and not in the signature." ([ordered]@{
                        Publisher = 'Embed the full chain (signer + intermediates) when signing: jsign --certfile chain.pem. If the CA is internal, users also need its root.'
                        You       = 'Ask the publisher for a build that includes the full chain, or ask IT to deploy the issuing CA.'
                    })
                }
                'NotValidForUsage' {
                    Add-Finding FAIL 'Chain' 'Certificate chain is not valid for code signing.' ([ordered]@{
                        Publisher = 'Use a certificate (and CA) issued for code signing.'
                    })
                }
                { $_ -in 'RevocationStatusUnknown', 'OfflineRevocation' } {
                    Add-Finding WARN 'Chain' 'Could not reach the certificate authority to check revocation.' ([ordered]@{
                        You       = 'Run the check again while online (or check that your proxy allows the CA''s CRL/OCSP addresses).'
                        Publisher = 'If the CA is internal, make sure its CRL/OCSP addresses in the certificate are reachable by your users.'
                    })
                }
                'NotTimeValid' {
                    if (-not ($daysLeft -lt 0 -and -not $hasTimestamp)) {   # already reported above
                        Add-Finding WARN 'Chain' 'A certificate in the chain is outside its validity period.' ([ordered]@{
                            Publisher = 'Renew the expired CA or signing certificate and re-sign with a timestamp.'
                        })
                    }
                }
                default {
                    Add-Finding WARN 'Chain' "Chain status: $s"
                }
            }
        }
    }
    $chain.Dispose()

    if ($embedded -and $embedded.EmbeddedCertCount -lt 2 -and -not $selfSigned -and $statuses -notcontains 'PartialChain') {
        Add-Finding WARN 'Chain' 'The signature includes only the signer''s certificate, not the issuing CA. It validates only on PCs that already have the intermediate CA.' ([ordered]@{
            Publisher = 'Pass the full chain (signer + intermediates) to the signing tool: jsign --certfile chain.pem, signtool /ac intermediate.cer.'
        })
    }

    # ---------------------------------------------------------- publisher identity
    Write-Section 'Publisher identity'
    if ($ExpectedPublisher) {
        if ($signerName -like "*$ExpectedPublisher*" -or $cert.Subject -like "*$ExpectedPublisher*") {
            Add-Finding PASS 'Publisher' "Signer matches the expected publisher '$ExpectedPublisher'."
        } else {
            Add-Finding FAIL 'Publisher' "Signer '$signerName' does NOT match the expected publisher '$ExpectedPublisher'." ([ordered]@{
                You = 'Do not run it: the file may be impersonating that publisher. Download it only from the publisher''s official site.'
            })
        }
    } else {
        Add-Finding INFO 'Publisher' 'No -ExpectedPublisher given; check that the signer above is the company you expect.'
    }
    if ($vi -and $vi.CompanyName) {
        $a = Get-NormalizedName $signerName
        $b = Get-NormalizedName $vi.CompanyName
        if ($a -and $b -and -not ($a.Contains($b) -or $b.Contains($a))) {
            Add-Finding WARN 'Publisher' "Signer '$signerName' differs from the CompanyName in the file '$($vi.CompanyName.Trim())'." ([ordered]@{
                Publisher = 'Make the CompanyName in the version resource match the organisation in the certificate (or sign with a certificate in the company''s legal name).'
                You       = 'Check that the signer really belongs to the company named in the file.'
            })
        } elseif ($a -and $b) {
            Add-Finding PASS 'Publisher' 'Signer matches the CompanyName in the file.'
        }
    }
} elseif ($ExpectedPublisher) {
    Add-Finding FAIL 'Publisher' "Expected publisher '$ExpectedPublisher' but the file is not signed." ([ordered]@{
        You = 'Do not run it; a genuine release from that publisher would be signed.'
    })
}

# ------------------------------------------------------------------ summary
Write-Section 'Summary'
$fails = @($script:Findings | Where-Object Level -eq 'FAIL')
$warns = @($script:Findings | Where-Object Level -eq 'WARN')
$passes = @($script:Findings | Where-Object Level -eq 'PASS')
Write-Host ("  {0} passed, {1} warnings, {2} failures" -f $passes.Count, $warns.Count, $fails.Count)

$todo = foreach ($f in ($fails + $warns)) { foreach ($a in $f.Actions) { [pscustomobject]@{ Owner = $a.Owner; Level = $f.Level; Action = $a.Action } } }
foreach ($owner in 'Publisher', 'You') {
    $items = @($todo | Where-Object Owner -eq $owner | Sort-Object Action -Unique | Sort-Object { if ($_.Level -eq 'FAIL') { 0 } else { 1 } })
    if ($items.Count) {
        $title = if ($owner -eq 'Publisher') { 'Actions for the PUBLISHER (who signs and ships the file):' } else { 'Actions for YOU (who downloaded the file):' }
        Write-Host ''
        Write-Host "  $title" -ForegroundColor Cyan
        foreach ($i in $items) { Write-Host ("    [{0}] {1}" -f $i.Level, $i.Action) -ForegroundColor $(if ($i.Level -eq 'FAIL') { 'Red' } else { 'Yellow' }) }
    }
}

if ($ReportPath) {
    try {
        if ($ReportPath -match '\.csv$') {
            $script:Findings | Select-Object Level, Area, Message,
                @{ n = 'Actions'; e = { ($_.Actions | ForEach-Object { "$($_.Owner): $($_.Action)" }) -join ' | ' } } |
                Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding UTF8
        } else {
            [pscustomobject]@{
                File = $full; Checked = (Get-Date).ToString('o'); Signer = $signerName
                SignatureStatus = "$($sig.Status)"; Findings = $script:Findings
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
        }
        Write-Host "  Report saved to $ReportPath" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not save report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
if ($fails.Count -gt 0) {
    Write-Host '  VERDICT: SIGNATURE NOT ACCEPTABLE. The publisher must fix the failures above before this file should be run.' -ForegroundColor Red
    $exitCode = 2
} elseif ($warns.Count -gt 0) {
    Write-Host '  VERDICT: SIGNATURE USABLE WITH WARNINGS. Review the actions above.' -ForegroundColor Yellow
    $exitCode = 1
} else {
    Write-Host '  VERDICT: Signature and certificate are in order.' -ForegroundColor Green
    $exitCode = 0
}
Write-Host '  A valid signature proves who published the file and that it is unchanged, not that it is harmless.' -ForegroundColor DarkGray
Write-Host '  Run Test-ExecutableEnvironment.ps1 for the local safety checks.' -ForegroundColor DarkGray
exit $exitCode
