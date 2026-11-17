<#
.SYNOPSIS
    One-step NetGuard setup for a single Windows machine: installs the dashboard AND the agent,
    connects them, and opens the dashboard. Normally started by double-clicking Setup.cmd.

.DESCRIPTION
    - Asks for administrator rights (UAC) if needed.
    - Dashboard -> C:\Program Files\NetGuard\dashboard, data in C:\ProgramData\NetGuard-Dashboard,
      runs at boot as SYSTEM, http://127.0.0.1:8787 (this PC only).
    - Agent     -> C:\ProgramData\NetGuard, scheduled task every minute as SYSTEM.
    - Safe mode (default): from the dashboard you can accept/trust listeners, kill processes and run
      audits on this PC, but hardening fixes and firewall changes are refused. Choose "full control"
      when asked (or pass -FullControl) to allow them.

      .\Install-NetGuard.ps1                  # interactive
      .\Install-NetGuard.ps1 -FullControl -Port 8790
      .\Install-NetGuard.ps1 -ShowLogin       # show how to sign in (local + Tailscale address)
      .\Install-NetGuard.ps1 -ResetPassword   # forgot password / lost 2FA phone: one-time password for 'admin'
      .\Install-NetGuard.ps1 -ResetPassword -User alice
      .\Install-NetGuard.ps1 -Uninstall       # removes tasks + programs, keeps alert data
      .\Install-NetGuard.ps1 -Uninstall -RemoveData
#>
[CmdletBinding()]
param(
    [int]$Port = 8787,
    [switch]$FullControl,
    [switch]$SafeMode,
    [switch]$Uninstall,
    [switch]$RemoveData,
    [switch]$ShowLogin,
    [switch]$ResetPassword,
    [string]$User = 'admin',
    [switch]$NoTailscale,
    [switch]$NoBrowser,
    [switch]$NoPause
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

function Invoke-Native([string]$exe, [string[]]$argv) {
    # Windows PowerShell 5.1 turns ANY stderr line of a program into a terminating error when
    # $ErrorActionPreference is 'Stop' (even with 2>$null). Run it with 'Continue' and use the exit code.
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $exe @argv 2>&1 | ForEach-Object { "$_" } | Out-String; return @{ code = $LASTEXITCODE; out = $out } }
    finally { $ErrorActionPreference = $old }
}
function Get-Tailscale {
    $c = (Get-Command tailscale.exe -ErrorAction SilentlyContinue).Source
    if (-not $c -and (Test-Path "$env:ProgramFiles\Tailscale\tailscale.exe")) { $c = "$env:ProgramFiles\Tailscale\tailscale.exe" }
    return $c
}
function Get-DashPython {
    $t = Get-ScheduledTask -TaskName 'NetGuard Dashboard' -ErrorAction SilentlyContinue
    if ($t) { return $t.Actions[0].Execute }
    return (Get-Command python.exe).Source
}
function Save-DashConfig($cfg) {
    [IO.File]::WriteAllText((Join-Path $env:ProgramData 'NetGuard-Dashboard\config.json'), (ConvertTo-Json -InputObject $cfg -Depth 4), (New-Object Text.UTF8Encoding($false)))
}
function Enable-RemoteAccess([int]$port) {
    # Publishes the dashboard ONLY to devices in your Tailscale network, with HTTPS. Nothing is opened to the internet.
    $ts = Get-Tailscale
    if (-not $ts) {
        Write-Host '  Tailscale is not installed, so the dashboard is only reachable on this PC.'
        Write-Host '  To use it from your phone/laptop and share it with other admins: install Tailscale'
        Write-Host '  (https://tailscale.com/download), sign in, then run Setup.cmd again.'
        return $null
    }
    $st = $null
    try { $st = & $ts status --json 2>$null | Out-String | ConvertFrom-Json } catch { }
    if (-not $st -or $st.BackendState -ne 'Running') {
        Write-Host '  Tailscale is installed but not connected. Open Tailscale, sign in, then run Setup.cmd again.'
        return $null
    }
    $name = "$($st.Self.DNSName)".TrimEnd('.')
    $ans = Read-Host "  Make the dashboard available to your Tailscale devices at https://$name ? [Y/n]"
    if ($ans -match '^[Nn]') { return $null }
    $r = Invoke-Native $ts @('serve', '--bg', '--https=443', "http://127.0.0.1:$port"); $out = $r.out
    if ($r.code -ne 0) {
        Write-Warning "tailscale serve failed:`n$out"
        Write-Host '  In the Tailscale admin console (DNS page) turn on MagicDNS and HTTPS Certificates, then run Setup.cmd again.'
        return $null
    }
    return "https://$name"
}

function Pause-End { if (-not $NoPause) { Write-Host ''; Read-Host 'Press Enter to close' | Out-Null } }

# ---- self-elevate --------------------------------------------------------------
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v) { $argList += "-$k" } } else { $argList += "-$k"; $argList += "$v" }
    }
    Write-Host 'Requesting administrator rights...'
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $argList | Out-Null }
    catch { Write-Host 'Setup needs administrator rights. Cancelled.' -ForegroundColor Red; Pause-End }
    return
}

$host.UI.RawUI.WindowTitle = 'NetGuard setup'
try {
    if ($ShowLogin -or $ResetPassword) {
        $cfgPath = Join-Path $env:ProgramData 'NetGuard-Dashboard\config.json'
        if (-not (Test-Path $cfgPath)) { throw 'NetGuard dashboard is not installed (no config found). Run Setup.cmd first.' }
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        $url = "http://127.0.0.1:$($cfg.listen_port)"
        Write-Host ''
        if ($ResetPassword) {
            $py = Get-DashPython
            $r = Invoke-Native $py @("$env:ProgramFiles\NetGuard\dashboard\server.py", '--config', $cfgPath, '--reset-user', $User); $out = $r.out
            if ($r.code -ne 0) { throw "reset failed: $out" }
            $pw = ([regex]::Match($out, 'One-time password: (\S+)')).Groups[1].Value
            try { Set-Clipboard -Value $pw } catch { }
            Write-Host "  Account '$User' reset." -ForegroundColor Green
            Write-Host "  One-time password : $pw   (copied to clipboard)"
            Write-Host '  Sign in with it; you then choose a new password and set up 2-factor again.'
            Write-Host '  All of that account''s devices were signed out.'
        } elseif ($cfg.admin_password) {
            try { Set-Clipboard -Value $cfg.admin_password } catch { }
            Write-Host "  First sign-in: user '$($cfg.admin_user)', one-time password $($cfg.admin_password)   (copied to clipboard)"
            Write-Host '  You choose your own password and set up 2-factor right after.'
        } else {
            Write-Host '  Sign in with your own NetGuard account (password + 2-factor code).'
            Write-Host '  Forgot it or lost your phone? Run:  Show-Login.cmd -ResetPassword   (or -ResetPassword -User <name>)'
        }
        Write-Host ''
        Write-Host "  On this PC  : $url"
        if ($cfg.remote_url) { Write-Host "  From anywhere (your Tailscale devices): $($cfg.remote_url)" }
        if (-not $NoBrowser) { Start-Process $url }
        Pause-End
        return
    }

    if ($Uninstall) {
        Write-Host 'Uninstalling NetGuard...' -ForegroundColor Cyan
        & (Join-Path $Root 'agents\windows\Install-Agent.ps1') -Uninstall
        & (Join-Path $Root 'dashboard\Install-Dashboard.ps1') -Uninstall -RemoveData:$RemoveData
        if ($RemoveData) {
            Remove-Item (Join-Path $env:ProgramData 'NetGuard') -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host 'Agent data removed. Hardening backups were in that folder too.'
        } else {
            Write-Host "Kept data: $env:ProgramData\NetGuard (agent state, hardening backups) and $env:ProgramData\NetGuard-Dashboard (alerts)."
        }
        Write-Host 'NetGuard removed.' -ForegroundColor Green
        Pause-End
        return
    }

    Write-Host ''
    Write-Host '  NetGuard setup - this PC will be monitored as a Windows server' -ForegroundColor Cyan
    Write-Host '  ---------------------------------------------------------------'
    if (-not $FullControl -and -not $SafeMode) {
        Write-Host ''
        Write-Host '  What may the dashboard do on this PC?'
        Write-Host '    [1] Safe mode (recommended for a personal PC): trust/accept listeners, kill processes, run audits.'
        Write-Host '        Hardening fixes and firewall changes are refused.'
        Write-Host '    [2] Full control: also apply hardening fixes, block IPs/ports (each one still needs your click + confirm).'
        $choice = Read-Host '  Choose 1 or 2 [1]'
        $FullControl = ($choice -eq '2')
    }

    Write-Host ''
    Write-Host '[1/4] Installing dashboard...' -ForegroundColor Cyan
    & (Join-Path $Root 'dashboard\Install-Dashboard.ps1') -Port $Port | Out-Host
    $cfg = Get-Content (Join-Path $env:ProgramData 'NetGuard-Dashboard\config.json') -Raw | ConvertFrom-Json
    $url = "http://127.0.0.1:$($cfg.listen_port)"

    Write-Host '[2/4] Installing agent...' -ForegroundColor Cyan
    $agentArgs = @{ Server = $url; Token = $cfg.agent_token }
    $pubFile = Join-Path $env:ProgramData 'NetGuard-Dashboard\command-signing.pub'
    foreach ($i in 1..20) { if (Test-Path $pubFile) { break }; Start-Sleep -Milliseconds 500 }
    if (Test-Path $pubFile) { $agentArgs.CommandKey = (Get-Content $pubFile -Raw).Trim() }
    if ($FullControl) { $agentArgs.FullControl = $true } else { $agentArgs.SafeMode = $true }
    $agentCfg = Join-Path $env:ProgramData 'NetGuard\agent.json'
    if (Test-Path $agentCfg) {
        # re-running setup: make sure the agent points at this dashboard with the current token
        $a = Get-Content $agentCfg -Raw | ConvertFrom-Json
        $a.server_url = $url; $a.agent_token = $cfg.agent_token
        ConvertTo-Json -InputObject $a -Depth 4 | Set-Content -Path $agentCfg -Encoding UTF8
    }
    & (Join-Path $Root 'agents\windows\Install-Agent.ps1') @agentArgs | Out-Host

    Write-Host '[3/4] Waiting for this PC to report in...' -ForegroundColor Cyan
    $py = Get-DashPython
    $check = "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); r=c.execute('SELECT last_seen FROM hosts WHERE lower(name)=lower(?)',(sys.argv[2],)).fetchone(); print('yes' if r and time.time()-r[0]<180 else 'no')"
    $seen = $false
    foreach ($i in 1..24) {   # up to ~2 minutes (first cycle also runs the hardening audit)
        Start-Sleep -Seconds 5
        $r = (Invoke-Native $py @('-c', $check, $cfg.db_path, $env:COMPUTERNAME)).out
        if ("$r".Trim() -eq 'yes') { $seen = $true; break }
        Write-Host '.' -NoNewline
    }
    Write-Host ''
    if ($seen) { Write-Host "  $env:COMPUTERNAME is reporting." -ForegroundColor Green }
    else { Write-Warning "Agent hasn't reported yet. Check $env:ProgramData\NetGuard\agent.log in a minute." }

    Write-Host '[4/4] Remote access...' -ForegroundColor Cyan
    $remote = $null
    if (-not $NoTailscale) { $remote = Enable-RemoteAccess ([int]$cfg.listen_port) }
    if ($remote) {
        $cfg = Get-Content (Join-Path $env:ProgramData 'NetGuard-Dashboard\config.json') -Raw | ConvertFrom-Json
        if ($cfg.PSObject.Properties['remote_url']) { $cfg.remote_url = $remote } else { $cfg | Add-Member -NotePropertyName remote_url -NotePropertyValue $remote }
        Save-DashConfig $cfg
    }

    Write-Host ''
    Write-Host '  NetGuard is installed and starts automatically with Windows.' -ForegroundColor Green
    Write-Host "  On this PC   : $url"
    if ($remote) { Write-Host "  From anywhere: $remote   (only devices in your Tailscale network)" -ForegroundColor Green }
    if ($cfg.admin_password) {
        try { Set-Clipboard -Value $cfg.admin_password } catch { }
        Write-Host "  First sign-in: user '$($cfg.admin_user)', one-time password $($cfg.admin_password)   (copied to clipboard)"
        Write-Host '                 You then choose your own password and set up 2-factor on your phone.'
    } else {
        Write-Host '  Sign in     : with your NetGuard account (password + 2-factor)'
    }
    Write-Host "  Mode        : $(if ($FullControl) { 'full control' } else { 'safe mode' })"
    Write-Host ''
    Write-Host '  Add other admins: People tab > Invite someone (send them the link privately).'
    if ($remote) { Write-Host "  Other servers' agents can report to: $remote" }
    Write-Host '  Forgot your password / lost your phone: Show-Login.cmd -ResetPassword'
    Write-Host '  Uninstall: double-click Uninstall.cmd'
    if (-not $NoBrowser) { Start-Process $url }
} catch {
    Write-Host ''
    Write-Host "Setup failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
Pause-End
