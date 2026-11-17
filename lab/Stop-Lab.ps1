<#
.SYNOPSIS
    Stops the NetGuard test lab. -Reset also deletes lab data (alerts DB, config, agent state).
#>
[CmdletBinding()]
param([switch]$Reset)
$Lab = Join-Path $PSScriptRoot '.labdata'
$pidFile = Join-Path $Lab 'pids.json'
if (Test-Path $pidFile) {
    $p = Get-Content $pidFile -Raw | ConvertFrom-Json
    foreach ($id in $p.dashboard, $p.windows_agent, $p.wsl) {
        if ($id -and (Get-Process -Id $id -ErrorAction SilentlyContinue)) { Stop-Process -Id $id -Force; Write-Host "stopped pid $id" }
    }
    if ($p.wsl -and $p.distro) {
        wsl.exe -d $p.distro -u root -- pkill -f 'netguard_agent.py --config /var/lib/netguard-lab' 2>$null | Out-Null
        Write-Host "stopped Linux agent in WSL '$($p.distro)'"
    }
    Remove-Item $pidFile -Force
} else { Write-Host 'Lab is not running.' }
if ($Reset) {
    Remove-Item $Lab -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Lab data deleted.'
}
