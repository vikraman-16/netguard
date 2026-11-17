<#
.SYNOPSIS
    Starts HARMLESS fake threats for a few minutes so you can see NetGuard alerts and practise
    resolving them in the dashboard. Nothing is installed or changed; every decoy exits on its own.

    Windows decoys (this PC):
      svchost.exe  - a copy of ping.exe renamed and run from the lab folder   -> "Fake Windows process" (critical)
      scvhost.exe  - same, look-alike name                                    -> "imitates svchost" (high)
      powershell listening on 127.0.0.1:18555                                -> abused tool holding a port (high)
      ng-unsigned-demo.exe listening on 127.0.0.1:18559 (compiled, unsigned) -> unsigned listener + "Trust process"
    Linux decoys (WSL, as your normal user): fake sshd from /tmp, look-alike 'sshdd', fake [kworker],
      fileless (memfd) process, nc listener, unpackaged listener.

      .\lab\Start-Decoys.ps1                 # 10 minutes, Windows + WSL
      .\lab\Start-Decoys.ps1 -Minutes 3 -NoLinux
#>
[CmdletBinding()]
param([int]$Minutes = 10, [string]$Distro = 'Ubuntu', [switch]$NoLinux)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Dir = Join-Path $PSScriptRoot '.labdata\decoys'
New-Item -ItemType Directory -Path $Dir -Force | Out-Null
$secs = $Minutes * 60

# Renamed copies of ping.exe: genuine Microsoft binary, wrong name/location
foreach ($n in 'svchost', 'scvhost') {
    $exe = Join-Path $Dir "$n.exe"
    Copy-Item "$env:SystemRoot\System32\PING.EXE" $exe -Force
    Start-Process $exe -ArgumentList "-n $secs 127.0.0.1" -WindowStyle Hidden
}

# PowerShell holding a listening port (loopback only)
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -Command `"`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,18555);`$l.Start();Start-Sleep $secs`""

# A tiny unsigned program listening on loopback (compiled locally, never signed)
$demo = Join-Path $Dir 'ng-unsigned-demo.exe'
if (-not (Test-Path $demo)) {
    Add-Type -OutputType ConsoleApplication -OutputAssembly $demo -TypeDefinition @'
using System; using System.Net; using System.Net.Sockets; using System.Threading;
public static class Program {
    public static void Main(string[] args) {
        int secs = args.Length > 0 ? int.Parse(args[0]) : 600;
        var l = new TcpListener(IPAddress.Loopback, 18559); l.Start();
        Thread.Sleep(secs * 1000); l.Stop();
    }
}
'@
}
Start-Process $demo -ArgumentList "$secs" -WindowStyle Hidden
Write-Host "Windows decoys running for $Minutes min." -ForegroundColor Green

if (-not $NoLinux) {
    $wslRoot = (wsl.exe -d $Distro -- wslpath -a "$Root").Trim()
    Start-Process wsl.exe -ArgumentList "-d $Distro -- bash `"$wslRoot/lab/decoys-linux.sh`" $secs" -WindowStyle Hidden
    Write-Host "Linux decoys running in WSL '$Distro' for $Minutes min." -ForegroundColor Green
}
Write-Host 'Alerts show up in the dashboard after the next agent cycle (<= 30 s).'
Write-Host 'Try: open each alert, read the playbook, then Kill / Trust / Accept / Suppress / Resolve.'
