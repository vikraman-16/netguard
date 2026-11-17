<#
.SYNOPSIS
    Installs the NetGuard dashboard on Windows as a startup task (runs as SYSTEM, restarts on failure).

.EXAMPLE
    .\Install-Dashboard.ps1                                  # http://127.0.0.1:8787, this PC only
    .\Install-Dashboard.ps1 -ListenAddress 0.0.0.0 -OpenFirewall -RemoteAddress 10.0.0.0/8
    .\Install-Dashboard.ps1 -Uninstall                       # keeps data unless -RemoveData

    Program : C:\Program Files\NetGuard\dashboard
    Data    : C:\ProgramData\NetGuard-Dashboard  (config.json with password + agent token, netguard.db)
#>
[CmdletBinding()]
param(
    [int]$Port = 8787,
    [string]$ListenAddress = '127.0.0.1',
    [switch]$OpenFirewall,
    [string[]]$RemoteAddress = @('LocalSubnet'),
    [switch]$Uninstall,
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$TaskName = 'NetGuard Dashboard'
$InstallDir = Join-Path $env:ProgramFiles 'NetGuard\dashboard'
$DataDir = Join-Path $env:ProgramData 'NetGuard-Dashboard'
$CfgPath = Join-Path $DataDir 'config.json'

if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell (Run as administrator).'
}

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName 'NetGuard Dashboard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like "*$InstallDir*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($RemoveData) { Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "Removed $DataDir" }
    Write-Host 'Dashboard uninstalled.'
    return
}

# Python must be a machine-wide install: SYSTEM can't use per-user Python or the Store stub.
$python = $null
foreach ($c in @(Get-Command python.exe, py.exe -All -ErrorAction SilentlyContinue)) {
    if ($c.Source -notmatch '\\Users\\|WindowsApps') { $python = $c.Source; break }
}
if (-not $python) { throw 'No machine-wide Python 3 found. Install Python from python.org with "Install for all users".' }
$ver = & $python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]'3.8') { throw "Python $ver is too old (need 3.8+)." }

# The dashboard encrypts stored secrets and signs agent commands with the 'cryptography' package.
# It runs as SYSTEM, which can't see per-user packages, so check and install with -s (no user site-packages)
# to get exactly SYSTEM's view, and install machine-wide.
& $python -s -c "import cryptography" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Installing the Python "cryptography" package for all users (needs internet)...'
    & $python -s -m pip install --disable-pip-version-check --quiet cryptography
    & $python -s -c "import cryptography" 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the Python "cryptography" package for all users. Check the internet connection, or run from an elevated prompt: python -s -m pip install cryptography' }
}

# ---- files -------------------------------------------------------------------
$src = $PSScriptRoot
# Upgrading: stop the running dashboard first, otherwise the old code keeps running after the files are replaced.
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='py.exe'" |
    Where-Object { $_.CommandLine -like "*$InstallDir*server.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $src '*.py') $InstallDir -Force
Copy-Item (Join-Path $src 'static') $InstallDir -Recurse -Force

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators only: config holds the password + agent token
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -Path $DataDir -AclObject $acl

function New-Secret([int]$bytes) {
    $b = New-Object byte[] $bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ([Convert]::ToBase64String($b) -replace '[+/=]', '')
}
$utf8 = New-Object Text.UTF8Encoding($false)   # Python's json rejects a BOM
if (Test-Path $CfgPath) {
    $cfg = Get-Content $CfgPath -Raw | ConvertFrom-Json
    $cfg.listen_host = $ListenAddress; $cfg.listen_port = $Port
    Write-Host 'Existing config kept (password and agent token unchanged).'
} else {
    $cfg = [pscustomobject][ordered]@{
        listen_host = $ListenAddress; listen_port = $Port; admin_user = 'admin'
        admin_password = (New-Secret 12); agent_token = (New-Secret 32)
        db_path = (Join-Path $DataDir 'netguard.db'); offline_after_seconds = 300; tls_cert = ''; tls_key = ''
    }
}
[IO.File]::WriteAllText($CfgPath, (ConvertTo-Json -InputObject $cfg -Depth 4), $utf8)

# ---- startup task ------------------------------------------------------------
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute $python -Argument "`"$InstallDir\server.py`" --config `"$CfgPath`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'NetGuard alert dashboard' | Out-Null
Start-ScheduledTask -TaskName $TaskName

if ($OpenFirewall) {
    Get-NetFirewallRule -DisplayName 'NetGuard Dashboard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'NetGuard Dashboard' -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress $RemoteAddress -Action Allow | Out-Null
    Write-Host "Firewall: allowed TCP $Port from $($RemoteAddress -join ', ')"
}

$probe = if ($ListenAddress -eq '0.0.0.0') { '127.0.0.1' } else { $ListenAddress }
$ok = $false
foreach ($i in 1..30) {
    Start-Sleep -Milliseconds 500
    try { Invoke-RestMethod "http://${probe}:$Port/healthz" -TimeoutSec 2 | Out-Null; $ok = $true; break } catch { }
}
if (-not $ok) {
    # show WHY: start the server the way SYSTEM would (no user packages) for a few seconds and capture its error
    $diag = Join-Path $env:TEMP 'netguard-dashboard-start.log'
    $pp = Start-Process $python -ArgumentList "-s `"$InstallDir\server.py`" --config `"$CfgPath`"" -RedirectStandardError $diag -PassThru -WindowStyle Hidden
    Start-Sleep 4; if (-not $pp.HasExited) { Stop-Process -Id $pp.Id -Force }
    $why = (Get-Content $diag -ErrorAction SilentlyContinue | Select-Object -Last 6) -join "`n"
    throw "Dashboard task started but http://${probe}:$Port/healthz is not answering.`n$why"
}

Write-Host ''
Write-Host "Dashboard running: http://${probe}:$Port   (starts automatically at boot)" -ForegroundColor Green
if ($cfg.admin_password) {
    Write-Host "  first sign-in : user '$($cfg.admin_user)', one-time password $($cfg.admin_password)"
    Write-Host '                  (you choose your own password and set up 2-factor right after)'
} else {
    Write-Host '  sign-in       : with your own NetGuard account (password + 2-factor)'
}
Write-Host "  agent token : $($cfg.agent_token)"
Write-Host "  config      : $CfgPath (admins only)"
if ($ListenAddress -ne '127.0.0.1' -and -not $cfg.tls_cert) {
    Write-Warning 'Listening on the network without TLS: the password and agent token travel in clear text. Use TLS or a reverse proxy before exposing it.'
}
