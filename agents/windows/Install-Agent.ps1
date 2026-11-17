<#
.SYNOPSIS
    Installs the NetGuard Windows agent as a scheduled task (every minute, as SYSTEM).

.EXAMPLE
    .\Install-Agent.ps1 -Server https://netguard.example.com:8787 -Token <agent_token>
    .\Install-Agent.ps1 -Server http://10.0.0.5:8787 -Token <t> -TrustedIps 10.0.0.5,10.0.0.0/24
    .\Install-Agent.ps1 -Server http://127.0.0.1:8787 -Token <t> -SafeMode   # personal PC / first try
    .\Install-Agent.ps1 -Uninstall

    -SafeMode limits what the dashboard may do on this host to: accept/trust listeners, quarantine,
    kill processes and run audits. Hardening fixes and firewall changes are refused.
    Re-run with -FullControl to lift that (config is updated in place).
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$Token,
    [string[]]$TrustedIps = @(),
    [switch]$Insecure,
    [switch]$NoFirewallLogging,
    [switch]$SafeMode,
    [switch]$FullControl,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Dir = Join-Path $env:ProgramData 'NetGuard'
$TaskName = 'NetGuard Agent'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell.'
}

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Dir 'NetGuard-Agent.ps1'), (Join-Path $Dir 'Harden-Server.ps1') -ErrorAction SilentlyContinue
    Write-Host "Removed task and scripts. Config/state/backups left in $Dir."
    return
}
if (-not $Server -or -not $Token) { throw 'Usage: .\Install-Agent.ps1 -Server URL -Token TOKEN' }
if ($SafeMode -and $FullControl) { throw 'Use either -SafeMode or -FullControl.' }
$SafeActions = @('accept_listener', 'allow_process', 'kill_process', 'quarantine_file', 'restore_quarantine', 'run_hardening_audit', 'unblock_ip', 'unblock_port', 'harden_restore')

New-Item -ItemType Directory -Path $Dir -Force | Out-Null
# Only SYSTEM and Administrators may touch the folder: the task runs these scripts as SYSTEM.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $acct = (New-Object Security.Principal.SecurityIdentifier $sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($acct, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -Path $Dir -AclObject $acl

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item (Join-Path $here 'NetGuard-Agent.ps1') $Dir -Force
$harden = Join-Path $here '..\..\hardening\windows\Harden-Server.ps1'
if (Test-Path $harden) { Copy-Item $harden $Dir -Force } else { Write-Warning 'Harden-Server.ps1 not found next to the agent; hardening audit disabled.' }

$cfgPath = Join-Path $Dir 'agent.json'
if (-not (Test-Path $cfgPath)) {
    $cfg = [ordered]@{
        server_url = $Server; agent_token = $Token; verify_tls = (-not $Insecure)
        harden_script = (Join-Path $Dir 'Harden-Server.ps1'); hardening_interval_minutes = 360
        blocklist_file = (Join-Path $Dir 'blocklist.txt'); trusted_ips = @($TrustedIps | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
        thresholds = [ordered]@{ auth_failures = 10; auth_window_seconds = 600; port_scan_ports = 15; conn_per_ip = 200
            rx_mbps = 500; tx_mbps = 500; cpu_pct = 90; cpu_cycles = 5; mem_pct = 90; disk_pct = 90 }
    }
    if ($SafeMode) { $cfg.allowed_actions = $SafeActions }
    ConvertTo-Json -InputObject $cfg -Depth 4 | Set-Content -Path $cfgPath -Encoding UTF8
} else {
    $cur = Get-Content $cfgPath -Raw | ConvertFrom-Json
    if ($SafeMode -or $FullControl) {
        $cur.PSObject.Properties.Remove('allowed_actions')
        if ($SafeMode) { $cur | Add-Member -NotePropertyName allowed_actions -NotePropertyValue $SafeActions }
        ConvertTo-Json -InputObject $cur -Depth 4 | Set-Content -Path $cfgPath -Encoding UTF8
        Write-Host "$cfgPath updated: $(if ($SafeMode) { 'safe mode' } else { 'full control' })"
    } else { Write-Host "$cfgPath exists - left unchanged" }
}
$bl = Join-Path $Dir 'blocklist.txt'
if (-not (Test-Path $bl)) { '# One IP or CIDR per line. Connections to/from these raise critical alerts.' | Set-Content $bl }

if (-not $NoFirewallLogging) {
    # Port-scan detection reads dropped packets from the firewall log.
    Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -LogMaxSizeKilobytes 16384
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dir\NetGuard-Agent.ps1`" -ConfigPath `"$cfgPath`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed. Task '$TaskName' runs every minute as SYSTEM.$(if ($SafeMode) { ' (safe mode)' })"
Write-Host "Log: $Dir\agent.log   Config: $cfgPath"
Write-Host 'First run records current listening ports as the baseline.'
