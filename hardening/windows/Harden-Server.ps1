<#
.SYNOPSIS
    NetGuard - Windows Server hardening (audit / apply / restore).

.DESCRIPTION
    Audits Windows Server security settings and, when asked, fixes them.
    Default mode is Audit: nothing is changed.

      .\Harden-Server.ps1                                  # audit only
      .\Harden-Server.ps1 -Mode Apply                      # fix failing checks, asks per check
      .\Harden-Server.ps1 -Mode Apply -Yes                 # fix everything without prompting
      .\Harden-Server.ps1 -Mode Apply -Only smb1_disabled,rdp_nla -Yes
      .\Harden-Server.ps1 -Skip legacy_tls_disabled
      .\Harden-Server.ps1 -Json C:\temp\report.json        # or -Json - for stdout
      .\Harden-Server.ps1 -List
      .\Harden-Server.ps1 -Restore C:\ProgramData\NetGuard\hardening-backups\20261117-104700

    Before every change the previous value is written to rollback.json in a
    timestamped backup folder; -Restore replays it in reverse.
    Run from an elevated PowerShell.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Apply')] [string]$Mode = 'Audit',
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [switch]$Yes,
    [string]$Json = '',
    [switch]$List,
    [string]$Restore = ''
)

$ErrorActionPreference = 'Stop'
$Version = '1.0.0'
$BackupRoot = Join-Path $env:ProgramData 'NetGuard\hardening-backups'
$BackupDir = Join-Path $BackupRoot (Get-Date -Format 'yyyyMMdd-HHmmss')
$LogFile = Join-Path $env:ProgramData 'NetGuard\hardening.log'
$script:Rollback = New-Object System.Collections.ArrayList
$script:Quiet = ($Json -eq '-')

# Allow comma-separated values when called from cmd / the agent
$Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Skip = @($Skip | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

function Out-Info([string]$msg, [string]$color = 'Gray') {
    if ($script:Quiet) { [Console]::Error.WriteLine($msg) } else { Write-Host $msg -ForegroundColor $color }
}
function Write-Log([string]$msg) {
    try {
        $d = Split-Path $LogFile
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Add-Content -Path $LogFile -Value ("{0} [{1}] {2}" -f (Get-Date -Format s), $Mode, $msg)
    } catch { }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$IsAdmin = Test-Admin
$IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)

# ---------------------------------------------------------------------------
# Backup / rollback helpers
# ---------------------------------------------------------------------------
function Initialize-Backup {
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
}
function Save-Rollback {
    Initialize-Backup
    $script:Rollback | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $BackupDir 'rollback.json') -Encoding UTF8
}
function Get-RegValue([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
function Set-RegValue([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    $existed = $false; $old = $null; $oldType = $null
    if (Test-Path $Path) {
        $item = Get-Item -Path $Path
        if ($item.GetValueNames() -contains $Name) {
            $existed = $true; $old = $item.GetValue($Name); $oldType = $item.GetValueKind($Name).ToString()
        }
    } else {
        New-Item -Path $Path -Force | Out-Null
    }
    [void]$script:Rollback.Add([pscustomobject]@{ kind = 'registry'; path = $Path; name = $Name; existed = $existed; old = $old; oldType = $oldType })
    Save-Rollback
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}
function Set-ServiceStart([string]$Name, [string]$StartType, [switch]$Stop) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    [void]$script:Rollback.Add([pscustomobject]@{ kind = 'service'; name = $Name; old = $svc.StartType.ToString(); wasRunning = ($svc.Status -eq 'Running') })
    Save-Rollback
    if ($Stop -and $svc.Status -eq 'Running') { Stop-Service -Name $Name -Force }
    Set-Service -Name $Name -StartupType $StartType
}

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
if ($Restore) {
    $rb = Join-Path $Restore 'rollback.json'
    if (-not (Test-Path $rb)) { throw "No rollback.json in $Restore" }
    $items = @(Get-Content $rb -Raw | ConvertFrom-Json)
    [array]::Reverse($items)
    foreach ($i in $items) {
        try {
            switch ($i.kind) {
                'registry' {
                    if ($i.existed) {
                        $val = $i.old
                        if ($i.oldType -eq 'MultiString') { $val = [string[]]$i.old }
                        New-ItemProperty -Path $i.path -Name $i.name -Value $val -PropertyType $i.oldType -Force | Out-Null
                    } else { Remove-ItemProperty -Path $i.path -Name $i.name -ErrorAction SilentlyContinue }
                    Write-Host "  restored $($i.path)\$($i.name)"
                }
                'service' {
                    Set-Service -Name $i.name -StartupType $i.old
                    if ($i.wasRunning) { Start-Service -Name $i.name -ErrorAction SilentlyContinue }
                    Write-Host "  restored service $($i.name) -> $($i.old)"
                }
                'smb' { Set-SmbServerConfiguration -EnableSMB1Protocol $i.smb1 -RequireSecuritySignature $i.signing -Force; Write-Host '  restored SMB server config' }
                'netaccounts' {
                    & net accounts "/minpwlen:$($i.minpwlen)" "/lockoutthreshold:$($i.lockout)" | Out-Null
                    Write-Host '  restored password/lockout policy'
                }
                'auditpol' { & auditpol /restore "/file:$($i.file)" | Out-Null; Write-Host '  restored audit policy' }
                'firewall' { & netsh advfirewall import "$($i.file)" | Out-Null; Write-Host '  restored firewall policy' }
                'mppref' { Set-MpPreference -DisableRealtimeMonitoring $i.old; Write-Host '  restored Defender realtime setting' }
                'eventlog' { & wevtutil sl $i.name "/ms:$($i.old)"; Write-Host "  restored $($i.name) log size" }
            }
        } catch { Write-Warning "  could not restore $($i.kind) $($i.name): $_" }
    }
    Write-Log "restore from $Restore"
    Write-Host 'Restore complete. Some settings (LSA protection, SCHANNEL) need a reboot.'
    exit 0
}

# ---------------------------------------------------------------------------
# Checks: each has Id, Severity, Title, Test (returns @{Status='pass|fail|na'; Detail=''}), optional Fix
# ---------------------------------------------------------------------------
function Res([string]$status, [string]$detail) { return @{ Status = $status; Detail = $detail } }
function Test-Reg([string]$Path, [string]$Name, $Want, [switch]$AbsentPasses, [string]$Label) {
    $v = Get-RegValue $Path $Name
    if ($null -eq $v) {
        if ($AbsentPasses) { return (Res 'pass' "$Label not set (secure default)") }
        return (Res 'fail' "$Label not set (want $Want)")
    }
    if ("$v" -eq "$Want") { return (Res 'pass' "$Label = $v") }
    return (Res 'fail' "$Label = $v (want $Want)")
}

$LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$SCHANNEL = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$AuditSubcats = [ordered]@{
    'Credential Validation'     = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Logon'                     = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Account Lockout'           = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'Special Logon'             = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Process Creation'          = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'User Account Management'   = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'       = '{0CCE922F-69AE-11D9-BED3-505054503030}'
}
function Get-AuditSetting([string]$guid) {
    # /r gives CSV; the "Inclusion Setting" column is index 4. Value text is localized,
    # so compare against both English text and the presence of two settings.
    $csv = & auditpol /get "/subcategory:$guid" /r 2>$null | Where-Object { $_ -and $_ -notmatch '^Machine Name' }
    if (-not $csv) { return $null }
    $cols = ($csv | Select-Object -First 1) -split ','
    return $cols[4]
}
function Get-SecPolicy {
    $tmp = Join-Path $env:TEMP ("ng-secpol-{0}.inf" -f [guid]::NewGuid())
    & secedit /export /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
    $h = @{}
    if (Test-Path $tmp) {
        Get-Content $tmp | ForEach-Object { if ($_ -match '^\s*(\w+)\s*=\s*(.+?)\s*$') { $h[$matches[1]] = $matches[2] } }
        Remove-Item $tmp -Force
    }
    return $h
}

# What each fix changes, what it can break, and whether it needs a reboot. Shown in the dashboard
# so the decision to apply a fix is an informed one.
$FixInfo = @{
    firewall_profiles        = @{ change = 'Turn Windows Firewall on for Domain/Private/Public and block unsolicited inbound traffic (allow rules for RDP/WinRM are added first if those are in use).'; risk = 'Programs that accept incoming connections without a firewall rule stop being reachable from other machines.'; reboot = $false }
    firewall_logging         = @{ change = 'Log dropped packets to pfirewall.log (max 16 MB) for all profiles.'; risk = 'None. Needed for port-scan detection.'; reboot = $false }
    smb1_disabled            = @{ change = 'Disable the SMBv1 file-sharing server.'; risk = 'Very old devices (Windows XP, old NAS boxes, old printers) can no longer open this PC''s shares.'; reboot = $false }
    smb_signing              = @{ change = 'Require signed SMB traffic for this PC''s shares.'; risk = 'Very old clients may fail to connect; file sharing gets slightly slower.'; reboot = $false }
    rdp_nla                  = @{ change = 'Require Network Level Authentication for Remote Desktop.'; risk = 'Very old Remote Desktop clients cannot connect.'; reboot = $false }
    llmnr_disabled           = @{ change = 'Policy: turn off LLMNR multicast name resolution.'; risk = 'Devices without a DNS name may have to be reached by IP or .local name.'; reboot = $false }
    wdigest_disabled         = @{ change = 'Set WDigest UseLogonCredential = 0 (no plaintext passwords in memory).'; risk = 'None on supported Windows versions.'; reboot = $false }
    lsa_protection           = @{ change = 'Run LSASS as a protected process (RunAsPPL = 1).'; risk = 'Old password-filter or security drivers that inject into LSASS fail to load.'; reboot = $true }
    ntlmv1_disabled          = @{ change = 'Set LmCompatibilityLevel = 5: send NTLMv2 only, refuse LM and NTLMv1.'; risk = 'Very old devices or apps that only speak NTLMv1 cannot authenticate to this PC.'; reboot = $false }
    anonymous_restricted     = @{ change = 'Block anonymous listing of accounts and shares (RestrictAnonymous = 1, RestrictAnonymousSAM = 1).'; risk = 'Legacy apps relying on anonymous (null) sessions stop working.'; reboot = $false }
    guest_disabled           = @{ change = 'Disable the built-in Guest account.'; risk = 'None.'; reboot = $false }
    password_length          = @{ change = 'Minimum local-account password length 14 (net accounts /minpwlen:14).'; risk = 'Applies at the next local password change. Microsoft-account and PIN sign-in are not affected.'; reboot = $false }
    account_lockout          = @{ change = 'Lock a local account for 15 minutes after 5 failed logons.'; risk = 'Mistyping your local password 5 times locks you out for 15 minutes.'; reboot = $false }
    audit_policy             = @{ change = 'Audit success and failure for logon, lockout, special logon, process creation, account and group changes; include command lines.'; risk = 'The Security log fills faster (pair with security_log_size).'; reboot = $false }
    security_log_size        = @{ change = 'Raise the Security event log maximum to 192 MB.'; risk = 'Uses up to 192 MB of disk.'; reboot = $false }
    defender_realtime        = @{ change = 'Turn Microsoft Defender real-time protection on.'; risk = 'Conflicts if another antivirus is meant to be the primary one.'; reboot = $false }
    defender_signatures      = @{ change = 'Download the latest Defender signatures now.'; risk = 'None.'; reboot = $false }
    uac_enabled              = @{ change = 'Enable User Account Control (EnableLUA = 1).'; risk = 'Admin tasks show consent prompts again.'; reboot = $true }
    autorun_disabled         = @{ change = 'Disable AutoRun on all drive types (NoDriveTypeAutoRun = 255).'; risk = 'USB sticks and discs no longer start programs automatically.'; reboot = $false }
    legacy_tls_disabled      = @{ change = 'Disable SSL 2.0/3.0 and TLS 1.0/1.1 for services this PC hosts.'; risk = 'Old clients connecting to services on this PC (IIS, SQL Server, old RDP clients) fail to connect.'; reboot = $true }
    ps_scriptblock_logging   = @{ change = 'Log the content of PowerShell scripts that run (event 4104).'; risk = 'More events in the PowerShell Operational log.'; reboot = $false }
    ps_v2_disabled           = @{ change = 'Remove the PowerShell 2.0 engine.'; risk = 'Very old scripts that require powershell -Version 2 stop working.'; reboot = $false }
    print_spooler_disabled   = @{ change = 'Stop and disable the Print Spooler service.'; risk = 'This machine can no longer print or share printers.'; reboot = $false }
    remote_registry_disabled = @{ change = 'Stop and disable the Remote Registry service.'; risk = 'Some remote management tools can no longer read this registry.'; reboot = $false }
    windows_update_enabled   = @{ change = 'Re-enable the Windows Update service (startup type Manual).'; risk = 'None.'; reboot = $false }
}

$Checks = @(
    @{ Id = 'firewall_profiles'; Severity = 'critical'; Title = 'Windows Firewall on for all profiles, inbound default block'
        Test = {
            $bad = Get-NetFirewallProfile | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -eq 'Allow' }
            if ($bad) { Res 'fail' ("profiles not protected: " + (($bad | ForEach-Object Name) -join ', ')) } else { Res 'pass' 'Domain/Private/Public enabled, inbound blocked' }
        }
        Fix = {
            Initialize-Backup
            $f = Join-Path $BackupDir 'firewall.wfw'
            & netsh advfirewall export "$f" | Out-Null
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'firewall'; file = $f }); Save-Rollback
            # Lock-out guard: keep remote management reachable before turning the firewall on.
            if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0) {
                $port = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
                if (-not $port) { $port = 3389 }
                if (-not (Get-NetFirewallRule -DisplayName 'NetGuard-Allow-RDP' -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName 'NetGuard-Allow-RDP' -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
                }
                "allowed RDP on TCP $port"
            }
            if ((Get-Service WinRM -ErrorAction SilentlyContinue).Status -eq 'Running' -and
                -not (Get-NetFirewallRule -DisplayName 'NetGuard-Allow-WinRM' -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName 'NetGuard-Allow-WinRM' -Direction Inbound -Protocol TCP -LocalPort 5985, 5986 -Action Allow | Out-Null
                'allowed WinRM 5985/5986'
            }
            Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        }
    }
    @{ Id = 'firewall_logging'; Severity = 'low'; Title = 'Firewall logs dropped packets'
        Test = {
            $bad = Get-NetFirewallProfile | Where-Object { $_.LogBlocked -ne 'True' }
            if ($bad) { Res 'fail' ("dropped-packet logging off for: " + (($bad | ForEach-Object Name) -join ', ')) } else { Res 'pass' 'dropped packets logged' }
        }
        Fix = { Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -LogMaxSizeKilobytes 16384 }
    }
    @{ Id = 'smb1_disabled'; Severity = 'high'; Title = 'SMBv1 server disabled'
        Test = { if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Res 'fail' 'SMBv1 is enabled (WannaCry/EternalBlue class risk)' } else { Res 'pass' 'SMBv1 disabled' } }
        Fix = {
            $c = Get-SmbServerConfiguration
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'smb'; smb1 = $c.EnableSMB1Protocol; signing = $c.RequireSecuritySignature }); Save-Rollback
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        }
    }
    @{ Id = 'smb_signing'; Severity = 'medium'; Title = 'SMB signing required (server)'
        Test = { if ((Get-SmbServerConfiguration).RequireSecuritySignature) { Res 'pass' 'SMB signing required' } else { Res 'fail' 'SMB signing not required (NTLM relay risk). Very old clients may fail to connect after fix.' } }
        Fix = {
            $c = Get-SmbServerConfiguration
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'smb'; smb1 = $c.EnableSMB1Protocol; signing = $c.RequireSecuritySignature }); Save-Rollback
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
        }
    }
    @{ Id = 'rdp_nla'; Severity = 'high'; Title = 'RDP requires Network Level Authentication'
        Test = { Test-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 -Label 'UserAuthentication' }
        Fix = { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 }
    }
    @{ Id = 'llmnr_disabled'; Severity = 'medium'; Title = 'LLMNR disabled (credential-poisoning risk)'
        Test = { Test-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 -Label 'EnableMulticast' }
        Fix = { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
    }
    @{ Id = 'wdigest_disabled'; Severity = 'high'; Title = 'WDigest plaintext credential caching off'
        Test = { Test-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -AbsentPasses -Label 'UseLogonCredential' }
        Fix = { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }
    }
    @{ Id = 'lsa_protection'; Severity = 'medium'; Title = 'LSA protection (RunAsPPL) - reboot required'
        Test = {
            $v = Get-RegValue $LSA 'RunAsPPL'
            if ($v -eq 1 -or $v -eq 2) { Res 'pass' "RunAsPPL = $v" } else { Res 'fail' "RunAsPPL = $v (want 1 or 2)" }
        }
        Fix = { Set-RegValue $LSA 'RunAsPPL' 1; 'reboot required to take effect' }
    }
    @{ Id = 'ntlmv1_disabled'; Severity = 'high'; Title = 'NTLMv1/LM refused (LmCompatibilityLevel 5)'
        Test = { Test-Reg $LSA 'LmCompatibilityLevel' 5 -Label 'LmCompatibilityLevel' }
        Fix = { Set-RegValue $LSA 'LmCompatibilityLevel' 5 }
    }
    @{ Id = 'anonymous_restricted'; Severity = 'medium'; Title = 'Anonymous SAM/share enumeration restricted'
        Test = {
            $a = Get-RegValue $LSA 'RestrictAnonymous'; $b = Get-RegValue $LSA 'RestrictAnonymousSAM'
            if ($a -ge 1 -and $b -ge 1) { Res 'pass' "RestrictAnonymous=$a RestrictAnonymousSAM=$b" } else { Res 'fail' "RestrictAnonymous=$a RestrictAnonymousSAM=$b (want 1/1)" }
        }
        Fix = { Set-RegValue $LSA 'RestrictAnonymous' 1; Set-RegValue $LSA 'RestrictAnonymousSAM' 1 }
    }
    @{ Id = 'guest_disabled'; Severity = 'high'; Title = 'Guest account disabled'
        Test = {
            $g = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -like '*-501' }
            if (-not $g) { Res 'na' 'no local Guest account (domain controller?)' }
            elseif ($g.Enabled) { Res 'fail' "$($g.Name) is enabled" } else { Res 'pass' "$($g.Name) disabled" }
        }
        Fix = { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser }
    }
    @{ Id = 'password_length'; Severity = 'medium'; Title = 'Local account passwords at least 14 characters'
        Test = {
            $p = Get-SecPolicy
            if (-not $p.Count) { return (Res 'na' 'could not read policy (needs admin)') }
            $len = [int]$p['MinimumPasswordLength']
            if ($len -ge 14) { Res 'pass' "MinimumPasswordLength=$len" } else { Res 'fail' "MinimumPasswordLength=$len (want >= 14)" }
        }
        Fix = {
            $p = Get-SecPolicy
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'netaccounts'; minpwlen = [int]$p['MinimumPasswordLength']; lockout = [int]$p['LockoutBadCount'] }); Save-Rollback
            & net accounts /minpwlen:14 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'net accounts failed (domain-joined? set via GPO)' }
            'applies the next time a local password is changed'
        }
    }
    @{ Id = 'account_lockout'; Severity = 'medium'; Title = 'Lock local accounts after 5 failed logons'
        Test = {
            $p = Get-SecPolicy
            if (-not $p.Count) { return (Res 'na' 'could not read policy (needs admin)') }
            $lock = [int]$p['LockoutBadCount']
            if ($lock -ge 1 -and $lock -le 10) { Res 'pass' "LockoutBadCount=$lock" } else { Res 'fail' "LockoutBadCount=$lock (0 = never lock; want 1-10). Password guessing is unlimited." }
        }
        Fix = {
            $p = Get-SecPolicy
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'netaccounts'; minpwlen = [int]$p['MinimumPasswordLength']; lockout = [int]$p['LockoutBadCount'] }); Save-Rollback
            & net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'net accounts failed (domain-joined? set via GPO)' }
        }
    }
    @{ Id = 'audit_policy'; Severity = 'high'; Title = 'Security auditing for logon, accounts, process creation'
        Test = {
            $missing = @()
            foreach ($k in $AuditSubcats.Keys) {
                $v = Get-AuditSetting $AuditSubcats[$k]
                if ($null -eq $v) { return (Res 'na' 'auditpol unavailable (needs admin)') }
                if ($v -notmatch 'Success and Failure') { $missing += "$k ($v)" }
            }
            if ($missing) { Res 'fail' ('not auditing success+failure: ' + ($missing -join '; ')) } else { Res 'pass' 'all key subcategories audited' }
        }
        Fix = {
            Initialize-Backup
            $f = Join-Path $BackupDir 'auditpol.csv'
            & auditpol /backup "/file:$f" | Out-Null
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'auditpol'; file = $f }); Save-Rollback
            foreach ($g in $AuditSubcats.Values) { & auditpol /set "/subcategory:$g" /success:enable /failure:enable | Out-Null }
            # include command line in process creation events
            Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
        }
    }
    @{ Id = 'security_log_size'; Severity = 'low'; Title = 'Security event log >= 192 MB'
        Test = {
            $l = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
            if (-not $l) { return (Res 'na' 'cannot read Security log (needs admin)') }
            $mb = [math]::Round($l.MaximumSizeInBytes / 1MB)
            if ($mb -ge 192) { Res 'pass' "$mb MB" } else { Res 'fail' "$mb MB (want >= 192, older events get overwritten fast)" }
        }
        Fix = {
            $l = Get-WinEvent -ListLog Security
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'eventlog'; name = 'Security'; old = $l.MaximumSizeInBytes }); Save-Rollback
            & wevtutil sl Security /ms:201326592
        }
    }
    @{ Id = 'defender_realtime'; Severity = 'high'; Title = 'Microsoft Defender real-time protection on'
        Test = {
            $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if (-not $s) { return (Res 'na' 'Defender not available') }
            if (-not $s.AMServiceEnabled) { return (Res 'na' 'Defender passive/disabled (3rd-party AV?)') }
            if ($s.RealTimeProtectionEnabled) { Res 'pass' 'real-time protection on' } else { Res 'fail' 'real-time protection OFF' }
        }
        Fix = {
            [void]$script:Rollback.Add([pscustomobject]@{ kind = 'mppref'; old = (Get-MpPreference).DisableRealtimeMonitoring }); Save-Rollback
            Set-MpPreference -DisableRealtimeMonitoring $false
        }
    }
    @{ Id = 'defender_signatures'; Severity = 'medium'; Title = 'Defender signatures updated in last 3 days'
        Test = {
            $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if (-not $s -or -not $s.AMServiceEnabled) { return (Res 'na' 'Defender not active') }
            if ($s.AntivirusSignatureAge -le 3) { Res 'pass' "signature age $($s.AntivirusSignatureAge) day(s)" } else { Res 'fail' "signatures $($s.AntivirusSignatureAge) days old" }
        }
        Fix = { Update-MpSignature }
    }
    @{ Id = 'uac_enabled'; Severity = 'high'; Title = 'User Account Control enabled'
        Test = { Test-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 -Label 'EnableLUA' }
        Fix = { Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1; 'reboot required' }
    }
    @{ Id = 'autorun_disabled'; Severity = 'low'; Title = 'AutoRun disabled for all drives'
        Test = { Test-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 -Label 'NoDriveTypeAutoRun' }
        Fix = { Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 }
    }
    @{ Id = 'legacy_tls_disabled'; Severity = 'medium'; Title = 'SSL 2/3, TLS 1.0/1.1 disabled for server - reboot required'
        Test = {
            $on = @()
            foreach ($p in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
                if ((Get-RegValue "$SCHANNEL\$p\Server" 'Enabled') -ne 0) { $on += $p }
            }
            if ($on) { Res 'fail' ('not explicitly disabled: ' + ($on -join ', ') + '. Check old clients/apps before fixing.') } else { Res 'pass' 'legacy protocols disabled' }
        }
        Fix = {
            foreach ($p in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
                Set-RegValue "$SCHANNEL\$p\Server" 'Enabled' 0
                Set-RegValue "$SCHANNEL\$p\Server" 'DisabledByDefault' 1
            }
            'reboot required'
        }
    }
    @{ Id = 'ps_scriptblock_logging'; Severity = 'medium'; Title = 'PowerShell script block logging'
        Test = { Test-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 -Label 'EnableScriptBlockLogging' }
        Fix = { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 }
    }
    @{ Id = 'ps_v2_disabled'; Severity = 'medium'; Title = 'PowerShell 2.0 engine removed (logging bypass)'
        Test = {
            try { $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop } catch { return (Res 'na' 'cannot query features (needs admin)') }
            if (-not $f -or $f.State -ne 'Enabled') { Res 'pass' 'PowerShell 2.0 not enabled' } else { Res 'fail' 'PowerShell 2.0 engine enabled' }
        }
        Fix = { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null }
    }
    @{ Id = 'print_spooler_disabled'; Severity = 'medium'; Title = 'Print Spooler disabled on non-print servers'
        Test = {
            if (-not $IsServer) { return (Res 'na' 'workstation OS') }
            $s = Get-Service Spooler -ErrorAction SilentlyContinue
            if (-not $s) { return (Res 'pass' 'Spooler not installed') }
            if ($s.StartType -eq 'Disabled') { Res 'pass' 'Spooler disabled' } else { Res 'fail' "Spooler is $($s.StartType)/$($s.Status) (PrintNightmare class risk). Keep it if this is a print server." }
        }
        Fix = { Set-ServiceStart Spooler Disabled -Stop }
    }
    @{ Id = 'remote_registry_disabled'; Severity = 'low'; Title = 'Remote Registry service disabled'
        Test = {
            $s = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
            if (-not $s -or $s.StartType -eq 'Disabled') { Res 'pass' 'disabled' } else { Res 'fail' "RemoteRegistry is $($s.StartType)" }
        }
        Fix = { Set-ServiceStart RemoteRegistry Disabled -Stop }
    }
    @{ Id = 'windows_update_enabled'; Severity = 'high'; Title = 'Windows Update service not disabled'
        Test = {
            $s = Get-Service wuauserv -ErrorAction SilentlyContinue
            if ($s -and $s.StartType -eq 'Disabled') { Res 'fail' 'wuauserv disabled - no security patches' } else { Res 'pass' 'wuauserv available' }
        }
        Fix = { Set-ServiceStart wuauserv Manual }
    }
)

if ($List) {
    $Checks | ForEach-Object { '{0,-28} {1,-9} {2}' -f $_.Id, $_.Severity, $_.Title }
    exit 0
}
if (-not $IsAdmin) { Out-Info 'Warning: not elevated; some checks will be n/a and -Mode Apply will fail.' 'Yellow' }

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
Out-Info "NetGuard hardening v$Version - mode: $Mode - host: $env:COMPUTERNAME" 'Cyan'
Write-Log "run started only=$($Only -join ',') skip=$($Skip -join ',')"
$results = @(); $pass = 0; $fail = 0; $fixed = 0; $err = 0; $na = 0

function Invoke-Test($c) {
    try { return (& $c.Test) } catch { return (Res 'na' "check error: $($_.Exception.Message)") }
}

foreach ($c in $Checks) {
    if ($Only.Count -and $Only -notcontains $c.Id) { continue }
    if ($Skip -contains $c.Id) { continue }
    $r = Invoke-Test $c
    $status = $r.Status; $detail = $r.Detail
    $fixable = [bool]$c.Fix

    switch ($status) {
        'na' { $na++; Out-Info ("  [ n/a ] {0} - {1}" -f $c.Id, $detail) 'DarkGray' }
        'pass' { $pass++; Out-Info ("  [ ok  ] {0} - {1}" -f $c.Id, $detail) 'Green' }
        'fail' {
            Out-Info ("  [FAIL ] {0} ({1}) - {2}" -f $c.Id, $c.Severity, $detail) 'Red'
            if ($Mode -eq 'Apply' -and $fixable) {
                $go = $Yes
                if (-not $go -and [Environment]::UserInteractive -and -not $script:Quiet) {
                    $go = ((Read-Host '    Apply fix? [y/N]') -match '^[Yy]')
                }
                if ($go) {
                    try {
                        $out = & $c.Fix 2>&1 | Out-String
                        if ($out.Trim()) { Out-Info ("    | " + ($out.Trim() -replace "`n", "`n    | ")) }
                        $r2 = Invoke-Test $c
                        if ($r2.Status -eq 'pass' -or $out -match 'reboot required') {
                            $status = 'fixed'; $fixed++; $detail = $r2.Detail
                            Out-Info '    fixed' 'Green'; Write-Log "fixed $($c.Id)"
                        } else { throw "still failing after fix: $($r2.Detail)" }
                    } catch {
                        $status = 'error'; $err++; $detail = "fix failed: $($_.Exception.Message)"
                        Out-Info "    $detail" 'Red'; Write-Log "fix failed $($c.Id): $($_.Exception.Message)"
                    }
                }
            }
            if ($status -eq 'fail') { $fail++ }
        }
    }
    $fi = $FixInfo[$c.Id]
    $results += [pscustomobject]@{ id = $c.Id; title = $c.Title; severity = $c.Severity; status = $status; fixable = $fixable; detail = $detail
        change = $(if ($fi) { $fi.change } else { '' }); risk = $(if ($fi) { $fi.risk } else { '' }); reboot = $(if ($fi) { [bool]$fi.reboot } else { $false }) }
}

Out-Info ''
Out-Info "Summary: $pass passed, $fail failing, $fixed fixed, $err errors, $na n/a" 'Cyan'
$backupUsed = (Test-Path (Join-Path $BackupDir 'rollback.json'))
if ($backupUsed) { Out-Info "Backup: $BackupDir   (undo: .\Harden-Server.ps1 -Restore `"$BackupDir`")" 'Yellow' }
if ($Mode -eq 'Audit' -and $fail -gt 0) { Out-Info 'Run with -Mode Apply to fix (you will be asked per check).' 'Yellow' }

if ($Json) {
    $doc = [pscustomobject]@{
        tool = 'netguard-harden'; version = $Version; os = 'windows'; host = $env:COMPUTERNAME
        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); mode = $Mode.ToLower()
        backup_dir = $(if ($backupUsed) { $BackupDir } else { '' }); results = $results
    }
    $text = $doc | ConvertTo-Json -Depth 5
    if ($Json -eq '-') { $text } else { $text | Set-Content -Path $Json -Encoding UTF8 }
}
Write-Log "run finished pass=$pass fail=$fail fixed=$fixed err=$err"
if ($fail -eq 0 -and $err -eq 0) { exit 0 } else { exit 1 }
