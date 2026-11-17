<#
  Windows agent detection test: starts harmless decoys (renamed copies of ping.exe), runs the agent in
  -DryRun mode (nothing is sent, nothing changed) and checks what it reports. Run as admin for full results.
      powershell -ExecutionPolicy Bypass -File tests\windows\Test-AgentTrust.ps1
#>
$ErrorActionPreference = 'Stop'
$Repo = Split-Path (Split-Path $PSScriptRoot)
$T = Join-Path $env:TEMP ("ng-agenttest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $T | Out-Null
$fail = 0
function Check($name, $cond) { if ($cond) { Write-Host "  PASS $name" -ForegroundColor Green } else { Write-Host "  FAIL $name" -ForegroundColor Red; $script:fail++ } }

Copy-Item "$env:SystemRoot\System32\PING.EXE" "$T\svchost.exe"
Copy-Item "$env:SystemRoot\System32\PING.EXE" "$T\scvhost.exe"
$p1 = Start-Process "$T\svchost.exe" -ArgumentList '-n 120 127.0.0.1' -WindowStyle Hidden -PassThru
$p2 = Start-Process "$T\scvhost.exe" -ArgumentList '-n 120 127.0.0.1' -WindowStyle Hidden -PassThru
$p3 = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile -Command "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,18555);$l.Start();Start-Sleep 120"'
Start-Sleep 2
try {
    @{ server_url = 'http://127.0.0.1:9'; agent_token = 'x'; host_name = 'TEST'; state_dir = "$T\state"; harden_script = '' } |
        ConvertTo-Json | Set-Content "$T\agent.json"
    New-Item -ItemType Directory "$T\state" | Out-Null
    '{"listen_baseline":[]}' | Set-Content "$T\state\agent-state.json"
    $r = & "$Repo\agents\windows\NetGuard-Agent.ps1" -ConfigPath "$T\agent.json" -DryRun | Out-String | ConvertFrom-Json
    $a = @($r.alerts)
    Check 'fake svchost.exe from a temp folder is critical masquerade' (@($a | Where-Object { $_.rule -eq 'process_masquerade' -and $_.severity -eq 'critical' -and $_.evidence.exe -eq "$T\svchost.exe" }).Count -eq 1)
    Check 'scvhost.exe flagged as look-alike' (@($a | Where-Object { $_.title -like "*'scvhost.exe' imitates*" }).Count -eq 1)
    Check 'powershell listener flagged as lolbin' (@($a | Where-Object { $_.title -like '*18555*' -and $_.evidence.trust -eq 'lolbin' }).Count -eq 1)
    Check 'quarantine offered for the fake svchost' (@($a | Where-Object { $_.evidence.exe -eq "$T\svchost.exe" } | ForEach-Object { $_.suggested.action }) -contains 'quarantine_file')
    Check 'no false masquerade for genuine Windows processes' (@($a | Where-Object { $_.rule -eq 'process_masquerade' -and $_.evidence.exe -like "$env:SystemRoot\*" }).Count -eq 0)
    Check 'capabilities reported' (@($r.capabilities.supported).Count -ge 10)
} finally {
    $p1, $p2, $p3 | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
}
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All Windows agent checks passed' -ForegroundColor Green }
