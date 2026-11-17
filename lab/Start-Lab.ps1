<#
.SYNOPSIS
    Starts a local NetGuard test lab on this PC - no servers needed.

.DESCRIPTION
      Dashboard ............ this PC, http://localhost:8787
      "Windows server" ..... this PC (agent runs in a loop, NOT installed as a service)
      "Linux server" ....... your WSL distro (agent runs as root inside WSL)

    Safety: on Windows the lab agent may only accept/trust listeners, kill processes
    and run audits. Firewall changes and hardening fixes are DISABLED unless you pass
    -AllowWindowsFixes, so clicking "Apply fix" can't change your real PC by accident.
    WSL is a disposable sandbox, so all actions are allowed there.

    Run from an elevated PowerShell for full results (otherwise Windows hides the
    paths of service processes and many show as "unknown").

      .\lab\Start-Lab.ps1
      .\lab\Start-Lab.ps1 -Distro Ubuntu -Port 8787
      .\lab\Start-Lab.ps1 -NoLinux
      .\lab\Stop-Lab.ps1
#>
[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu',
    [int]$Port = 8787,
    [int]$Interval = 30,
    [switch]$NoLinux,
    [switch]$AllowWindowsFixes,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Lab = Join-Path $PSScriptRoot '.labdata'
New-Item -ItemType Directory -Path $Lab -Force | Out-Null
$Utf8 = New-Object Text.UTF8Encoding($false)   # Python's json module rejects a BOM
function Write-Json($path, $obj) { [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $obj -Depth 5), $Utf8) }
function New-Secret([int]$bytes) {
    $b = New-Object byte[] $bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ([Convert]::ToBase64String($b) -replace '[+/=]', '')
}

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { throw 'Python 3 not found on PATH (needed for the dashboard).' }

$pidFile = Join-Path $Lab 'pids.json'
if (Test-Path $pidFile) {
    $old = Get-Content $pidFile -Raw | ConvertFrom-Json
    if (Get-Process -Id $old.dashboard -ErrorAction SilentlyContinue) { throw 'Lab already running. Use .\lab\Stop-Lab.ps1 first.' }
}

# ---- dashboard config (created once, reused) -------------------------------
$cfgPath = Join-Path $Lab 'config.json'
if (-not (Test-Path $cfgPath)) {
    Write-Json $cfgPath ([ordered]@{
            listen_host = '0.0.0.0'; listen_port = $Port; admin_user = 'admin'
            admin_password = (New-Secret 12); agent_token = (New-Secret 32)
            db_path = 'lab.db'; offline_after_seconds = [Math]::Max(120, $Interval * 4)
        })
}
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$Port = [int]$cfg.listen_port

Write-Host "Starting dashboard on port $Port ..." -ForegroundColor Cyan
$dash = Start-Process $python -ArgumentList "`"$Root\dashboard\server.py`" --config `"$cfgPath`"" `
    -WorkingDirectory "$Root\dashboard" -PassThru -WindowStyle Minimized
$ok = $false
foreach ($i in 1..30) {
    Start-Sleep -Milliseconds 500
    try { Invoke-RestMethod "http://127.0.0.1:$Port/healthz" -TimeoutSec 2 | Out-Null; $ok = $true; break } catch { }
}
if (-not $ok) { throw "Dashboard did not start. Is port $Port in use? Try -Port 8788." }

# ---- Windows agent (this PC) -----------------------------------------------
$allowed = @('accept_listener', 'allow_process', 'kill_process', 'quarantine_file', 'restore_quarantine', 'run_hardening_audit', 'unblock_ip', 'unblock_port', 'harden_restore', 'backup_run', 'backup_test', 'backup_restore')
$winCfg = [ordered]@{
    server_url = "http://127.0.0.1:$Port"; agent_token = $cfg.agent_token; host_name = "$env:COMPUTERNAME"
    state_dir = (Join-Path $Lab 'win-state'); harden_script = (Join-Path $Root 'hardening\windows\Harden-Server.ps1')
    hardening_interval_minutes = 60
}
if (-not $AllowWindowsFixes) { $winCfg.allowed_actions = $allowed }
$winCfgPath = Join-Path $Lab 'win-agent.json'
Write-Json $winCfgPath $winCfg
$loop = Join-Path $Lab 'win-agent-loop.ps1'
[IO.File]::WriteAllText($loop, @"
`$host.UI.RawUI.WindowTitle = 'NetGuard lab - Windows agent'
Write-Host 'NetGuard Windows agent (lab). Close this window or run Stop-Lab.ps1 to stop.'
while (`$true) {
    try { & '$Root\agents\windows\NetGuard-Agent.ps1' -ConfigPath '$winCfgPath' } catch { Write-Warning `$_ }
    Write-Host ("{0}  cycle done" -f (Get-Date -Format T))
    Start-Sleep -Seconds $Interval
}
"@, $Utf8)
$win = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$loop`"" -PassThru -WindowStyle Minimized
Write-Host "Windows agent started (every $Interval s)$(if (-not $isAdmin) { ' - NOT elevated, results will be limited' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })

# ---- Linux agent (WSL) -----------------------------------------------------
$wslProc = $null
if (-not $NoLinux) {
    $distros = (wsl.exe -l -q) -replace "`0", '' | Where-Object { $_.Trim() }
    if ($distros -notcontains $Distro) {
        Write-Warning "WSL distro '$Distro' not found (have: $($distros -join ', ')). Skipping Linux. Use -Distro <name>."
    } else {
        $wslRoot = (wsl.exe -d $Distro -- wslpath -a $Root.Replace('\', '/')).Trim()
        $wslProc = Start-Process wsl.exe -ArgumentList "-d $Distro -u root -- bash `"$wslRoot/lab/run-linux-agent.sh`" $Port $($cfg.agent_token) $Interval" `
            -PassThru -WindowStyle Minimized
        Write-Host "Linux agent started in WSL '$Distro' (as root)" -ForegroundColor Green
    }
}

Write-Json $pidFile ([ordered]@{ dashboard = $dash.Id; windows_agent = $win.Id; wsl = $(if ($wslProc) { $wslProc.Id } else { 0 }); distro = $Distro })

Write-Host ''
Write-Host "Dashboard:  http://localhost:$Port" -ForegroundColor Cyan
Write-Host "User:       admin"
Write-Host "Password:   $($cfg.admin_password)"
Write-Host ''
Write-Host 'Hosts appear within ~1 minute. Then try:  .\lab\Start-Decoys.ps1   (safe fake threats)'
Write-Host 'Stop with:  .\lab\Stop-Lab.ps1'
if (-not $AllowWindowsFixes) { Write-Host 'Windows fixes/firewall actions are disabled in the lab (-AllowWindowsFixes to enable).' -ForegroundColor DarkGray }
if (-not $NoBrowser) { Start-Process "http://localhost:$Port" }
