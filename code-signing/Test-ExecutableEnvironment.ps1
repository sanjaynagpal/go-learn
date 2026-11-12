#Requires -Version 5.1
<#
.SYNOPSIS
    Checks a downloaded Windows executable against THIS PC before you run it, without judging its
    code signature, and says what you (or your IT administrator) can do about each problem.

.DESCRIPTION
    Everything here can be checked and mitigated locally by the user or IT.

    The file is never executed. Checks:
      1. File identity  - SHA-256 (optionally against the vendor's hash), deceptive names, PE header,
                          version info, Mark of the Web (download source), hidden data streams.
      2. Antivirus      - Microsoft Defender status and an on-demand scan of just this file.
      3. App Control    - WDAC user-mode enforcement, active policies, Smart App Control, AppLocker,
                          past Code Integrity block events, and a prediction of whether it will be blocked.
                          (The prediction reads whether the signature is valid, but does not check it.)
      4. Permissions    - Execute rights, whether others can replace the file or plant DLLs next to it.

    Every warning or failure comes with an action for:
      - You       : what you can do on this PC
      - IT admin  : what needs an administrator or a policy change
      - Publisher : only where the local fix is "ask the publisher"

    Exit code: 0 = no problems, 1 = warnings, 2 = failures.

.PARAMETER Path
    The file to check.

.PARAMETER ExpectedSha256
    The SHA-256 hash the vendor publishes on their download page.

.PARAMETER SkipDefenderScan
    Do not run the Microsoft Defender scan.

.PARAMETER ReportPath
    Optional path to save the findings and actions as .json or .csv.

.EXAMPLE
    .\Test-ExecutableEnvironment.ps1 -Path "$env:USERPROFILE\Downloads\setup.exe" -ExpectedSha256 3A7B...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,
    [string]$ExpectedSha256,
    [switch]$SkipDefenderScan,
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
        [System.Collections.IDictionary]$Do      # ordered @{ You = '...'; 'IT admin' = '...' }
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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------------------------------------------ 1. file
Write-Section 'File'

try {
    $item = Get-Item -LiteralPath $Path -Force
} catch {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 2
}
if ($item.PSIsContainer) { Write-Host "$Path is a folder, not a file." -ForegroundColor Red; exit 2 }
$full = $item.FullName
$name = $item.Name

Add-Finding INFO 'File' "Path: $full"
Add-Finding INFO 'File' ("Size: {0:N0} bytes, last written {1}" -f $item.Length, $item.LastWriteTime)
if (-not $isAdmin) {
    Add-Finding INFO 'File' 'Running without Administrator rights; the Code Integrity event log and full policy list may be unavailable.'
}

$sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
Add-Finding INFO 'File' "SHA-256: $sha256"
if ($ExpectedSha256) {
    if ($sha256 -eq $ExpectedSha256.Trim()) {
        Add-Finding PASS 'File' 'SHA-256 matches the expected hash.'
    } else {
        Add-Finding FAIL 'File' "SHA-256 does NOT match the expected hash ($($ExpectedSha256.Trim()))." ([ordered]@{
            You       = 'Delete the file and download it again from the official site over HTTPS. Check you copied the right hash (version, architecture).'
            Publisher = 'If a fresh download still does not match, tell the publisher: their download or published hash is wrong.'
        })
    }
} else {
    Add-Finding INFO 'File' 'No -ExpectedSha256 given.' ([ordered]@{
        You = 'If the vendor publishes a SHA-256 hash, run again with -ExpectedSha256 <hash>.'
    })
}
Add-Finding INFO 'File' "Look up the hash (no upload): https://www.virustotal.com/gui/file/$sha256"

if ($name -match '[‪-‮⁦-⁩‎‏]') {
    Add-Finding FAIL 'File' 'File name contains hidden Unicode direction characters, a trick used to disguise the real extension.' ([ordered]@{
        You = 'Do not run it. Delete the file; legitimate software does not do this.'
    })
}
if ($name -match '(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp[34]|zip|rar)\.(exe|scr|com|bat|cmd|msi|pif|js|vbs|ps1|lnk)$') {
    Add-Finding FAIL 'File' "File name has a double extension ($name), a common way to disguise a program as a document." ([ordered]@{
        You = 'Do not run it. Delete the file. Turn on "File name extensions" in Explorer (View menu) to spot this.'
    })
}
if ($item.Attributes -band [IO.FileAttributes]::Hidden -or $item.Attributes -band [IO.FileAttributes]::System) {
    Add-Finding WARN 'File' "File has Hidden/System attributes: $($item.Attributes)" ([ordered]@{
        You = 'Downloads are not normally hidden. Find out why before running it; attrib -h -s <file> shows it normally.'
    })
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
                        Subsystem = $subsystem; DllCharacteristics = $dllChars; IsDotNet = ($clrSize -gt 0)
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
        Add-Finding WARN 'File' "File is a Windows executable but has the extension '$ext'." ([ordered]@{
            You = 'Do not rename it to .exe to run it. Ask the source why a program was sent with this extension.'
        })
    }
    $missing = @()
    if (-not ($pe.DllCharacteristics -band 0x0040)) { $missing += 'ASLR' }
    if (-not ($pe.DllCharacteristics -band 0x0100)) { $missing += 'DEP/NX' }
    if ($missing) {
        Add-Finding INFO 'File' "Built without exploit mitigations: $($missing -join ', ') (common in old or hand-made tools)." ([ordered]@{
            You = 'If you are unsure about it, try it first in Windows Sandbox or a virtual machine.'
        })
    }
} elseif ($ext -eq '.msi') {
    Add-Finding INFO 'File' 'Windows Installer package (.msi).'
} else {
    Add-Finding WARN 'File' 'File is not a Windows PE executable (no MZ/PE header).' ([ordered]@{
        You = 'Check what kind of file this really is before opening it.'
    })
}

try {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
    $viText = @()
    foreach ($p in 'CompanyName', 'ProductName', 'FileDescription', 'FileVersion', 'OriginalFilename') {
        if ($vi.$p) { $viText += "$p='$($vi.$p.Trim())'" }
    }
    if ($viText) { Add-Finding INFO 'File' ("Version info (self-declared): " + ($viText -join '; ')) }
} catch { }

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
    Add-Finding INFO 'File' 'Keep the mark until you decide to run the file.' ([ordered]@{
        You = 'Check that HostUrl is the publisher''s real domain. Don''t use Unblock-File until every check passes.'
    })
    if ($zoneId -eq '4') {
        Add-Finding WARN 'File' 'File came from a Restricted-sites zone.' ([ordered]@{
            You = 'You or IT marked that site as untrusted. Get the file from the publisher''s official site instead.'
        })
    }
} else {
    Add-Finding WARN 'File' 'No Mark of the Web. SmartScreen and Smart App Control will not get a chance to check it.' ([ordered]@{
        You = 'If it came from the internet, download it again with a browser, or extract it with Windows'' built-in zip support (some tools strip the mark). Otherwise rely on the antivirus scan and the hash.'
    })
}
try {
    $streams = Get-Item -LiteralPath $full -Stream * -ErrorAction Stop |
        Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen' }
    foreach ($s in $streams) {
        Add-Finding WARN 'File' ("Extra hidden data stream '{0}' ({1:N0} bytes)." -f $s.Stream, $s.Length) ([ordered]@{
            You = "Inspect it: Get-Content -LiteralPath '$full' -Stream '$($s.Stream)'. Remove it if unexpected: Remove-Item -LiteralPath '$full' -Stream '$($s.Stream)'."
        })
    }
} catch { }

# ------------------------------------------------------------------ 2. Defender
Write-Section 'Microsoft Defender'

if ($SkipDefenderScan) {
    Add-Finding INFO 'Antivirus' 'Defender scan skipped (-SkipDefenderScan).'
} else {
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($mpStatus.AMRunningMode -and $mpStatus.AMRunningMode -ne 'Normal') {
            Add-Finding INFO 'Antivirus' "Defender running mode: $($mpStatus.AMRunningMode) (another antivirus may be primary)." ([ordered]@{
                You = 'Also scan the file with your main antivirus (right-click > Scan).'
            })
        }
        if (-not $mpStatus.RealTimeProtectionEnabled) {
            Add-Finding WARN 'Antivirus' 'Defender real-time protection is OFF.' ([ordered]@{
                You       = 'If no other antivirus is active, turn it on: Windows Security > Virus & threat protection > Manage settings.'
                'IT admin' = 'If it is off by policy, confirm another antivirus or EDR covers this PC.'
            })
        }
        $sigAge = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalDays
        if ($sigAge -gt 7) {
            Add-Finding WARN 'Antivirus' ("Defender definitions are {0:N0} days old." -f $sigAge) ([ordered]@{
                You = 'Update them (Update-MpSignature, or Windows Security > Protection updates), then run this check again.'
            })
        }
    } catch {
        Add-Finding INFO 'Antivirus' 'Could not read Defender status (another antivirus may be installed).' ([ordered]@{
            You = 'Scan the file with your installed antivirus.'
        })
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
            Add-Finding FAIL 'Antivirus' "Defender DETECTED A THREAT. $threats" ([ordered]@{
                You = 'Do not run it. Delete it (or let Defender quarantine it) and run a full scan: Start-MpScan -ScanType FullScan.'
            })
        } else {
            Add-Finding WARN 'Antivirus' "Defender scan did not complete (exit code $code)." ([ordered]@{
                You = 'Scan it manually: right-click the file > Scan with Microsoft Defender, or use your installed antivirus.'
            })
        }
    } else {
        Add-Finding WARN 'Antivirus' 'MpCmdRun.exe not found.' ([ordered]@{
            You = 'Scan the file with your installed antivirus.'
        })
    }
}

# ------------------------------------------------------------------ 3. App Control
Write-Section 'App Control for Business (WDAC), Smart App Control, AppLocker'

# Signature validity is only READ here, as an input to the blocking prediction.
$sigStatus = 'Unknown'; $signerName = $null
try {
    $s = Get-AuthenticodeSignature -LiteralPath $full
    $sigStatus = "$($s.Status)"
    if ($s.SignerCertificate) { $signerName = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
} catch { }
$sigValid = ($sigStatus -eq 'Valid')
Add-Finding INFO 'AppControl' "Signature status used for the prediction: $sigStatus$(if ($signerName) { " (signer: $signerName)" }). Details: Test-ExecutableSignature.ps1"

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
        }
    } catch { }
}

switch ($umci) {
    2 {
        if (-not $sigValid) {
            Add-Finding WARN 'AppControl' 'BLOCK EXPECTED: user-mode App Control is enforced and the file is not validly signed.' ([ordered]@{
                'IT admin' = 'If the file is approved, allow it by hash in a supplemental App Control policy.'
                Publisher  = 'Ask the publisher for a correctly signed build, so IT can allow it by publisher instead of by hash.'
            })
        } else {
            Add-Finding WARN 'AppControl' "User-mode App Control is ENFORCED. The file runs only if a policy trusts '$signerName', its hash or a managed installer." ([ordered]@{
                'IT admin' = "Confirm a policy allows signer '$signerName' (FilePublisher or Publisher rule), or add a supplemental policy."
                You        = 'If it is blocked, look for event 3077 in Event Viewer > Microsoft > Windows > CodeIntegrity > Operational and send it to IT.'
            })
        }
    }
    1 { Add-Finding INFO 'AppControl' 'App Control is in audit mode: it will not block, but logs event 3076 if the file would have been blocked.' }
    0 { Add-Finding PASS 'AppControl' 'No enforced user-mode App Control policy: WDAC will not block this file.' }
}

$sacState = $null
try {
    $sacState = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop).VerifiedAndReputablePolicyState
} catch { }
switch ($sacState) {
    1 {
        Add-Finding INFO 'AppControl' 'Smart App Control: ON'
        if (-not $sigValid) {
            Add-Finding WARN 'AppControl' 'BLOCK LIKELY: Smart App Control blocks unsigned or invalidly signed apps unless Microsoft''s cloud already knows them as safe.' ([ordered]@{
                You       = 'Don''t turn Smart App Control off to run one app: it can''t be turned back on without resetting Windows. Ask the publisher for a validly signed build.'
                Publisher = 'Sign the file with a certificate from a CA in the Microsoft Trusted Root Program, with a timestamp.'
            })
        } else {
            Add-Finding PASS 'AppControl' 'Smart App Control generally allows apps with a valid signature from a trusted certificate authority.'
        }
    }
    2 { Add-Finding INFO 'AppControl' 'Smart App Control: Evaluation mode (not blocking yet).' }
    0 { Add-Finding INFO 'AppControl' 'Smart App Control: Off.' }
    default { Add-Finding INFO 'AppControl' 'Smart App Control: not available on this system.' }
}

try {
    $since = (Get-Date).AddDays(-30)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033, 3034, 3076, 3077; StartTime = $since
    } -MaxEvents 5000 -ErrorAction Stop | Where-Object { $_.Message -like "*$name*" }
    if ($events) {
        foreach ($e in ($events | Select-Object -First 5)) {
            $what = switch ($e.Id) { 3077 { 'BLOCKED by App Control' } 3076 { 'would be blocked (audit)' } 3033 { 'blocked: signing level not met' } 3034 { 'would be blocked: signing level (audit)' } }
            Add-Finding WARN 'AppControl' ("{0:yyyy-MM-dd HH:mm} event {1}: {2}" -f $e.TimeCreated, $e.Id, $what) ([ordered]@{
                'IT admin' = 'Review the event (it names the policy and the rule that did not match) and add a supplemental rule if the file is approved.'
            })
        }
    } else {
        Add-Finding INFO 'AppControl' 'No Code Integrity block or audit events for this file name in the last 30 days.'
    }
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Add-Finding INFO 'AppControl' 'No Code Integrity block or audit events in the last 30 days.'
    } else {
        Add-Finding INFO 'AppControl' 'Could not read the Code Integrity event log.' ([ordered]@{
            You = 'Run the script as Administrator for this check.'
        })
    }
}

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
                Add-Finding WARN 'AppControl' "AppLocker decision for ${user}: $decision. The file will be blocked if the collection is enforced." ([ordered]@{
                    'IT admin' = 'If the file is approved, add an AppLocker publisher or hash rule for it.'
                })
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

# ------------------------------------------------------------------ 4. permissions
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
$FSR = [Security.AccessControl.FileSystemRights]
$fileWriteMask = [int]($FSR::WriteData -bor $FSR::AppendData -bor $FSR::Delete -bor $FSR::ChangePermissions -bor $FSR::TakeOwnership)
$dirWriteMask  = [int]($FSR::CreateFiles -bor $FSR::CreateDirectories -bor $FSR::ChangePermissions -bor $FSR::TakeOwnership)
$GENERIC_ALL = 0x10000000; $GENERIC_WRITE = 0x40000000
$moveTip = 'Create a new folder in your own profile (e.g. %USERPROFILE%\Installers\<name>), move the file there, and run it from there.'

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
        Add-Finding WARN 'Permissions' 'Execute permission is explicitly DENIED for you; the file will not start.' ([ordered]@{
            'IT admin' = 'A deny rule is usually deliberate. Ask IT whether this file or folder is meant to be blocked.'
        })
    } elseif ($allow -band $execBit) {
        Add-Finding PASS 'Permissions' "You ($($me.Name)) have Read & Execute permission on the file."
    } else {
        Add-Finding WARN 'Permissions' 'No Execute permission is granted to you on this file; Windows will refuse to start it.' ([ordered]@{
            You = "Move the file to a folder you own, or grant yourself Read & Execute: icacls `"$full`" /grant `"$($me.Name):(RX)`""
        })
    }

    foreach ($r in $fileAcl.Rules) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -eq 'Allow' -and $broadSids.ContainsKey($sid)) {
            $bits = [int]$r.FileSystemRights
            if (($bits -band $fileWriteMask) -or ($bits -band ($GENERIC_ALL -bor $GENERIC_WRITE))) {
                Add-Finding WARN 'Permissions' "'$($broadSids[$sid])' can modify or replace this file ($($r.FileSystemRights)). Another user or process could swap it after you check it." ([ordered]@{
                    You = "$moveTip Then run this check again on the moved file."
                })
            }
        }
    }

    $parent = $item.DirectoryName
    $dirAcl = Get-AclRules $parent
    $dirWritable = $false
    foreach ($r in $dirAcl.Rules) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -eq 'Allow' -and $broadSids.ContainsKey($sid)) {
            $bits = [int]$r.FileSystemRights
            if (($bits -band $dirWriteMask) -or ($bits -band ($GENERIC_ALL -bor $GENERIC_WRITE))) {
                $dirWritable = $true
                Add-Finding WARN 'Permissions' "Folder '$parent' is writable by '$($broadSids[$sid])'. Other users could plant DLLs that this program loads." ([ordered]@{
                    You = $moveTip
                })
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
        Add-Finding WARN 'Permissions' "$($dlls.Count) DLL file(s) sit next to the program ($list). A program can load DLLs from its own folder." ([ordered]@{
            You = "$moveTip This stops stray downloaded DLLs from being side-loaded."
        })
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

$todo = foreach ($f in ($fails + $warns)) { foreach ($a in $f.Actions) { [pscustomobject]@{ Owner = $a.Owner; Level = $f.Level; Action = $a.Action } } }
$titles = [ordered]@{
    'You'       = 'Actions for YOU (on this PC):'
    'IT admin'  = 'Actions for your IT ADMINISTRATOR:'
    'Publisher' = 'Ask the PUBLISHER:'
}
foreach ($owner in $titles.Keys) {
    $items = @($todo | Where-Object Owner -eq $owner | Sort-Object Action -Unique | Sort-Object { if ($_.Level -eq 'FAIL') { 0 } else { 1 } })
    if ($items.Count) {
        Write-Host ''
        Write-Host "  $($titles[$owner])" -ForegroundColor Cyan
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
                File = $full; Sha256 = $sha256; Checked = (Get-Date).ToString('o'); Findings = $script:Findings
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
        }
        Write-Host "  Report saved to $ReportPath" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not save report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
if ($fails.Count -gt 0) {
    Write-Host '  VERDICT: DO NOT RUN. One or more local checks failed (see actions above).' -ForegroundColor Red
    $exitCode = 2
} elseif ($warns.Count -gt 0) {
    Write-Host '  VERDICT: REVIEW the warnings and take the actions above before running.' -ForegroundColor Yellow
    $exitCode = 1
} else {
    Write-Host '  VERDICT: No local problems found.' -ForegroundColor Green
    $exitCode = 0
}
Write-Host '  No automated check can prove a file is safe. Only run software from sources you trust.' -ForegroundColor DarkGray
exit $exitCode
