<#
.SYNOPSIS
    NetGuard Windows monitoring agent (PowerShell 5.1+).

.DESCRIPTION
    One run = one cycle. Install-Agent.ps1 registers a scheduled task that runs it
    every minute as SYSTEM. Each cycle:
      1. collects TCP/UDP endpoints, Security event log (4625/4624), firewall drop log,
         CPU/memory/disk/network counters, firewall + Defender state
      2. evaluates detection rules and builds alerts
      3. posts a report to the dashboard, receives remediation commands you approved,
         executes them (allow-listed + validated) and reports results
      4. periodically runs Harden-Server.ps1 -Mode Audit

      .\NetGuard-Agent.ps1 -ConfigPath C:\ProgramData\NetGuard\agent.json
      .\NetGuard-Agent.ps1 -ConfigPath ... -DryRun     # print report, send nothing
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $env:ProgramData 'NetGuard\agent.json'),
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$AgentVersion = '1.2.0'

# ---------------------------------------------------------------------------
# Config & state
# ---------------------------------------------------------------------------
$Defaults = @{
    server_url = 'http://127.0.0.1:8787'; agent_token = ''; host_name = ''; verify_tls = $true
    state_dir = (Join-Path $env:ProgramData 'NetGuard')
    harden_script = (Join-Path $env:ProgramData 'NetGuard\Harden-Server.ps1')
    hardening_interval_minutes = 360
    blocklist_file = (Join-Path $env:ProgramData 'NetGuard\blocklist.txt')
    trusted_ips = @()
    trust_microsoft_signed = $true   # auto-trust listeners from validly Microsoft-signed binaries (LOLBins excluded)
    trusted_signers = @()            # e.g. 'VMware, Inc.', 'Python Software Foundation' (matched against the cert's O=)
    process_allowlist = @()          # e.g. @{ name='nginx'; path='C:\nginx\nginx.exe'; signer='' ; sha256='' ; allow_unsigned=$false }
    suspicious_ports = @(23, 1337, 2323, 4444, 4445, 5554, 5555, 6666, 6667, 6668, 6669, 7777, 9001, 12345, 31337, 54321)
    thresholds = @{ auth_failures = 10; auth_window_seconds = 600; port_scan_ports = 15; conn_per_ip = 200
        rx_mbps = 500; tx_mbps = 500; cpu_pct = 90; cpu_cycles = 5; mem_pct = 90; disk_pct = 90 }
}

function ConvertTo-HashtableDeep($obj) {
    if ($null -eq $obj) { return $null }
    # NB: '-is [pscustomobject]' is true for ANY PSObject-wrapped value (even strings), so test scalars first.
    if ($obj -is [string] -or $obj -is [ValueType]) { return $obj }
    if ($obj -is [System.Collections.IDictionary]) { $h = @{}; foreach ($k in $obj.Keys) { $h[$k] = ConvertTo-HashtableDeep $obj[$k] }; return $h }
    if ($obj -is [System.Management.Automation.PSCustomObject]) { $h = @{}; foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-HashtableDeep $p.Value }; return $h }
    if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) { return , @($obj | ForEach-Object { ConvertTo-HashtableDeep $_ }) }
    return $obj
}

$cfg = $Defaults.Clone()
if (Test-Path $ConfigPath) {
    $user = ConvertTo-HashtableDeep (Get-Content $ConfigPath -Raw | ConvertFrom-Json)
    foreach ($k in $user.Keys) {
        if ($k -eq 'thresholds') { foreach ($t in $user.thresholds.Keys) { $cfg.thresholds[$t] = $user.thresholds[$t] } }
        else { $cfg[$k] = $user[$k] }
    }
} elseif (-not $DryRun) { throw "Config not found: $ConfigPath" }
$th = $cfg.thresholds
$HostName = if ($cfg.host_name) { $cfg.host_name } else { $env:COMPUTERNAME }
if (-not (Test-Path $cfg.state_dir)) { New-Item -ItemType Directory -Path $cfg.state_dir -Force | Out-Null }
$StatePath = Join-Path $cfg.state_dir 'agent-state.json'
$LogPath = Join-Path $cfg.state_dir 'agent.log'

function Write-AgentLog([string]$m) {
    $line = '{0} {1}' -f (Get-Date -Format s), $m
    try {
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 5MB) { Move-Item $LogPath "$LogPath.1" -Force }
        Add-Content -Path $LogPath -Value $line
    } catch { }
    Write-Verbose $line
}

$State = @{}
if (Test-Path $StatePath) {
    try { $State = ConvertTo-HashtableDeep (Get-Content $StatePath -Raw | ConvertFrom-Json) } catch { Write-AgentLog 'state unreadable, starting fresh' }
}
function Save-State {
    if ($script:SigCache) {
        $keep = @{}
        foreach ($k in $script:SigCache.Keys) { if ($Now - [long]$script:SigCache[$k].checked -lt 86400) { $keep[$k] = $script:SigCache[$k] } }
        if ($keep.Count -gt 600) { $keep = @{} }
        $State['sig_cache'] = $keep
    }
    ($State | ConvertTo-Json -Depth 8 -Compress) | Set-Content -Path $StatePath -Encoding UTF8
}
$Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Test-InNet([string]$ip, [string]$cidr) {
    try {
        $parts = $cidr.Trim() -split '/'
        $a = [Net.IPAddress]::Parse($ip); $n = [Net.IPAddress]::Parse($parts[0])
        if ($a.AddressFamily -ne $n.AddressFamily) { return $false }
        $ab = $a.GetAddressBytes(); $nb = $n.GetAddressBytes()
        $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { $ab.Length * 8 }
        for ($i = 0; $i -lt $ab.Length; $i++) {
            $take = [Math]::Max(0, [Math]::Min(8, $bits - 8 * $i))
            if ($take -eq 0) { break }
            $mask = [byte](0xFF -shl (8 - $take) -band 0xFF)
            if (($ab[$i] -band $mask) -ne ($nb[$i] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}
function Test-InList([string]$ip, $list) { foreach ($c in @($list)) { if ($c -and (Test-InNet $ip $c)) { return $true } }; return $false }
function Test-LocalAddr([string]$ip) { return ($ip -match '^(127\.|0\.0\.0\.0$|::1?$|::ffff:127\.)' -or -not $ip) }

# ---------------------------------------------------------------------------
# Process inventory
# ---------------------------------------------------------------------------
if (-not ('NgProc' -as [type])) {
    # QueryFullProcessImageName with PROCESS_QUERY_LIMITED_INFORMATION works even for
    # protected processes (lsass/csrss/MsMpEng) where Win32_Process.ExecutablePath is empty.
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class NgProc {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder buf, ref int size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static string ImagePath(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try { var sb = new StringBuilder(1024); int n = sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null; }
        finally { CloseHandle(h); }
    }
}
'@
}

$script:ProcTable = @{}
$ProcCache = @{}
function Update-ProcTable {
    $script:ProcTable = @{}; $ProcCache.Clear(); $TrustCache.Clear()
    foreach ($p in Get-CimInstance Win32_Process) { $script:ProcTable[[int]$p.ProcessId] = $p }
}
function Get-ProcInfo([int]$procId) {
    if ($ProcCache.ContainsKey($procId)) { return $ProcCache[$procId] }
    $info = @{ name = ''; path = ''; cmdline = ''; ppid = 0; created = $null }
    $p = $script:ProcTable[$procId]
    if (-not $p) { try { $p = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop } catch { } }
    if ($p) {
        $path = "$($p.ExecutablePath)"
        if (-not $path -and $procId -gt 4) { try { $path = "$([NgProc]::ImagePath($procId))" } catch { } }
        if ($path.StartsWith('\\?\')) { $path = $path.Substring(4) }   # strip Win32 long-path prefix
        $cmd = "$($p.CommandLine)"; if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) }
        $info = @{ name = ($p.Name -replace '\.exe$', ''); path = $path; cmdline = $cmd; ppid = [int]$p.ParentProcessId; created = $p.CreationDate }
    }
    $ProcCache[$procId] = $info
    return $info
}

# ---------------------------------------------------------------------------
# Process trust: built-in Windows allowlist + Authenticode signature checks
# ---------------------------------------------------------------------------
$SR = $env:SystemRoot; $PF = $env:ProgramFiles; $PD = $env:ProgramData
function S32([string[]]$names) { $h = @{}; foreach ($n in $names) { $h[$n] = @("$SR\System32\$n.exe") }; return $h }
# Core Windows processes and the ONLY places they may run from. They must also carry a valid Microsoft signature.
$WinAllow = @{}
$coreS32 = S32 @('lsass', 'lsaiso', 'services', 'wininit', 'csrss', 'smss', 'winlogon', 'spoolsv', 'dwm', 'fontdrvhost',
    'taskhostw', 'sihost', 'ctfmon', 'RuntimeBroker', 'SearchIndexer', 'SecurityHealthService', 'audiodg', 'WUDFHost',
    'msdtc', 'dns', 'dfsrs', 'ismserv', 'vmcompute', 'vmms', 'vmwp', 'rdpclip', 'LogonUI', 'userinit', 'wlanext', 'dasHost')
foreach ($k in $coreS32.Keys) { $WinAllow[$k] = $coreS32[$k] }
$WinAllow['svchost'] = @("$SR\System32\svchost.exe", "$SR\SysWOW64\svchost.exe")
$WinAllow['dllhost'] = @("$SR\System32\dllhost.exe", "$SR\SysWOW64\dllhost.exe")
$WinAllow['conhost'] = @("$SR\System32\conhost.exe")
$WinAllow['WmiPrvSE'] = @("$SR\System32\wbem\WmiPrvSE.exe", "$SR\SysWOW64\wbem\WmiPrvSE.exe")
$WinAllow['unsecapp'] = @("$SR\System32\wbem\unsecapp.exe", "$SR\SysWOW64\wbem\unsecapp.exe")
$WinAllow['explorer'] = @("$SR\explorer.exe")
$WinAllow['TextInputHost'] = @("$SR\SystemApps\*\TextInputHost.exe")
$WinAllow['w3wp'] = @("$SR\System32\inetsrv\w3wp.exe", "$SR\SysWOW64\inetsrv\w3wp.exe")
$WinAllow['inetinfo'] = @("$SR\System32\inetsrv\inetinfo.exe")
$WinAllow['TrustedInstaller'] = @("$SR\servicing\TrustedInstaller.exe")
$WinAllow['TiWorker'] = @("$SR\WinSxS\*\TiWorker.exe")
$WinAllow['Microsoft.ActiveDirectory.WebServices'] = @("$SR\ADWS\Microsoft.ActiveDirectory.WebServices.exe")
foreach ($n in 'MsMpEng', 'NisSrv', 'MpDefenderCoreService') {
    $WinAllow[$n] = @("$PD\Microsoft\Windows Defender\Platform\*\$n.exe", "$PF\Windows Defender\$n.exe")
}
# Expected parent process (a fake lsass started by something else is a classic sign of compromise)
$ExpectedParent = @{ lsass = @('wininit'); lsaiso = @('wininit'); services = @('wininit'); svchost = @('services', 'MsMpEng'); spoolsv = @('services') }
# Kernel / pseudo processes that have no executable file
$KernelPseudo = @('System', 'Idle', 'Registry', 'Memory Compression', 'Secure System', 'vmmem', 'vmmemWSL', 'MemCompression')
# Microsoft-signed binaries attackers love to abuse ("living off the land"): never auto-trusted
$LolBins = @('powershell', 'pwsh', 'powershell_ise', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin',
    'msbuild', 'installutil', 'regasm', 'regsvcs', 'msiexec', 'wmic', 'forfiles', 'cmstp', 'odbcconf', 'msxsl', 'csc', 'jsc', 'ftp', 'tftp', 'curl', 'nc', 'ncat')
$LookAlikeTargets = @('svchost', 'lsass', 'services', 'wininit', 'csrss', 'winlogon', 'explorer', 'spoolsv', 'taskhostw', 'conhost', 'dllhost', 'rundll32', 'MsMpEng', 'smss')
$Trusted = @('system', 'allowlisted', 'trusted_signer')

$TrustCache = @{}
$script:SigCache = @{}
if ($State['sig_cache']) { foreach ($k in $State['sig_cache'].Keys) { $script:SigCache[$k] = $State['sig_cache'][$k] } }

function Get-SigInfo([string]$path) {
    $none = @{ status = 'NoFile'; signer = ''; subject = ''; thumbprint = ''; microsoft = $false; checked = $Now }
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $none }
    $fi = Get-Item -LiteralPath $path -Force
    $key = '{0}|{1}|{2}' -f $path.ToLower(), $fi.Length, $fi.LastWriteTimeUtc.Ticks
    $c = $script:SigCache[$key]
    if ($c -and ($Now - [long]$c.checked) -lt 86400) { return $c }   # re-verify daily (catches revoked certs / timestomping)
    $s = $null
    try { $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop } catch { }
    $subj = ''; $thumb = ''
    if ($s -and $s.SignerCertificate) { $subj = $s.SignerCertificate.Subject; $thumb = $s.SignerCertificate.Thumbprint }
    $signer = ''
    if ($subj -match 'O="?([^",]+)') { $signer = $matches[1].Trim() } elseif ($subj -match 'CN="?([^",]+)') { $signer = $matches[1].Trim() }
    $status = if ($s) { $s.Status.ToString() } else { 'Unknown' }
    $r = @{ status = $status; signer = $signer; subject = $subj; thumbprint = $thumb; checked = $Now
        microsoft = ($status -eq 'Valid' -and $subj -match 'O=Microsoft (Corporation|Windows)') }
    $script:SigCache[$key] = $r
    return $r
}

function Get-Sha256([string]$path) {
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Find-Allowlisted([string]$name, [string]$path, $sig) {
    foreach ($e in @($cfg.process_allowlist) + @($State['process_allowlist'])) {
        if (-not $e -or -not $e.name -or $e.name -ne $name) { continue }
        if ($e.path -and $path -notlike $e.path) { continue }
        if ($e.sha256) {
            if ((Get-Sha256 $path) -eq $e.sha256) { return "allowlisted (SHA256 pinned)" }
            continue
        }
        if ($e.signer) {
            if ($sig.status -eq 'Valid' -and $sig.signer -like $e.signer) { return "allowlisted (signer '$($sig.signer)')" }
            continue
        }
        if ($sig.status -eq 'Valid' -or $e.allow_unsigned) { return 'allowlisted' }
    }
    return $null
}

function Get-ProcessTrust([int]$procId, $pi) {
    if ($TrustCache.ContainsKey($procId)) { return $TrustCache[$procId] }
    $t = @{ trust = 'unknown'; reason = ''; sig_status = ''; signer = ''; thumbprint = ''; sha256 = '' }
    $name = $pi.name
    if ($procId -le 4 -or (($KernelPseudo -contains $name -or $name -like 'vmmem*') -and -not $pi.path -and ($pi.ppid -le 4))) {
        $t.trust = 'system'; $t.reason = 'kernel / pseudo process'
    } elseif (-not $pi.path) {
        $t.reason = $(if ($WinAllow.ContainsKey($name)) { "cannot verify Windows $name.exe: executable path unreadable - run the agent as SYSTEM (Install-Agent.ps1 does)" } else { 'cannot read executable path - run the agent as SYSTEM' })
    } else {
        $sig = Get-SigInfo $pi.path
        $t.sig_status = $sig.status; $t.signer = $sig.signer; $t.thumbprint = $sig.thumbprint
        $expected = $WinAllow[$name]
        $pathOk = $false
        if ($expected) { foreach ($e in $expected) { if ($pi.path -like $e) { $pathOk = $true } } }
        $allow = $null
        if (-not $expected) { $allow = Find-Allowlisted $name $pi.path $sig }
        if ($expected -and -not $pathOk) {
            $t.trust = 'masquerade'; $t.reason = "named like Windows '$name.exe' but runs from $($pi.path) (expected $($expected -join ' or '))"
        } elseif ($expected -and $sig.microsoft) {
            $t.trust = 'system'; $t.reason = 'Windows component at its expected path with a valid Microsoft signature'
        } elseif ($expected) {
            $t.trust = 'masquerade'; $t.reason = "Windows '$name.exe' at the expected path but signature is $($sig.status) (signer '$($sig.signer)') - file may have been replaced"
        } elseif ($allow) {
            $t.trust = 'allowlisted'; $t.reason = $allow
        } elseif ($sig.status -eq 'Valid' -and @($cfg.trusted_signers | Where-Object { $_ -and $sig.signer -like $_ }).Count) {
            $t.trust = 'trusted_signer'; $t.reason = "signed by trusted publisher '$($sig.signer)'"
        } elseif ($sig.microsoft -and $LolBins -contains $name) {
            $t.trust = 'lolbin'; $t.reason = "Microsoft-signed $name.exe - commonly abused by attackers, never auto-trusted"
        } elseif ($sig.microsoft) {
            $t.trust = $(if ($cfg.trust_microsoft_signed) { 'trusted_signer' } else { 'signed' }); $t.reason = 'valid Microsoft signature'
        } elseif ($sig.status -eq 'Valid') {
            $t.trust = 'signed'; $t.reason = "valid signature from '$($sig.signer)' (publisher not in trusted_signers)"
        } elseif ($sig.status -eq 'NotSigned') {
            $t.trust = 'unsigned'; $t.reason = 'executable has no digital signature'
        } else {
            $t.trust = 'bad_signature'; $t.reason = "signature status '$($sig.status)' - tampered, expired or untrusted certificate"
        }
        if ($t.trust -notin 'system', 'trusted_signer') { $t.sha256 = Get-Sha256 $pi.path }
    }
    $TrustCache[$procId] = $t
    return $t
}

function Get-TrustEvidence($t) {
    $ev = @{ trust = $t.trust; trust_reason = $t.reason }
    if ($t.sig_status) { $ev.signature = $t.sig_status }
    if ($t.signer) { $ev.signer = $t.signer }
    if ($t.thumbprint) { $ev.cert_thumbprint = $t.thumbprint }
    if ($t.sha256) { $ev.sha256 = $t.sha256 }
    return $ev
}
function Merge-Hash($a, $b) { foreach ($k in $b.Keys) { $a[$k] = $b[$k] }; return $a }

function Get-Levenshtein([string]$a, [string]$b) {
    # Damerau (optimal string alignment) distance: swapped neighbours (scvhost/svchost) count as 1 edit
    $a = $a.ToLower(); $b = $b.ToLower()
    $pp = $null; $prev = [int[]](0..$b.Length)
    for ($i = 1; $i -le $a.Length; $i++) {
        $cur = New-Object int[] ($b.Length + 1)
        $cur[0] = $i
        for ($j = 1; $j -le $b.Length; $j++) {
            $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
            $del = $prev[$j] + 1; $ins = $cur[$j - 1] + 1; $sub = $prev[$j - 1] + $cost
            $v = [Math]::Min([Math]::Min($del, $ins), $sub)
            if ($i -gt 1 -and $j -gt 1 -and $a[$i - 1] -eq $b[$j - 2] -and $a[$i - 2] -eq $b[$j - 1]) { $v = [Math]::Min($v, $pp[$j - 2] + 1) }
            $cur[$j] = $v
        }
        $pp = $prev; $prev = $cur
    }
    return $prev[$b.Length]
}
function Get-LookAlike([string]$name) {
    if ($name.Length -lt 5 -or $WinAllow.ContainsKey($name)) { return $null }
    foreach ($target in $LookAlikeTargets) {
        if ([Math]::Abs($target.Length - $name.Length) -gt 1 -or $target -eq $name) { continue }
        if ((Get-Levenshtein $name $target) -le 1) { return $target }
    }
    return $null
}

$Alerts = New-Object System.Collections.ArrayList
$Conditions = New-Object System.Collections.Generic.HashSet[string]
function Add-Alert($rule, $severity, $fp, $title, $details, $evidence, $suggested, [switch]$Condition) {
    [void]$Alerts.Add(@{ rule = $rule; severity = $severity; fingerprint = $fp; title = $title; details = "$details"
            evidence = $(if ($evidence) { $evidence } else { @{} }); suggested = @($suggested | Where-Object { $_ }) })
    if ($Condition) { [void]$Conditions.Add($fp) }
}
function Sug($action, $params, $label) { return @{ action = $action; params = $params; label = $label } }

function Get-ListenerKey([string]$proto, [int]$port, [string]$proc) {
    # Windows hands out dynamic RPC ports (49152+) that change across reboots - key those by process instead.
    if ($port -ge 49152) { return "${proto}:dyn:$proc" }
    return "${proto}:$port"
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
function Invoke-SocketRules {
    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 49152 })
    $listeners = @{}
    foreach ($l in @($tcp | Where-Object State -eq 'Listen') + $udp) {
        $proto = if ($l.PSObject.Properties['State']) { 'tcp' } else { 'udp' }
        $pi = Get-ProcInfo $l.OwningProcess
        $key = Get-ListenerKey $proto $l.LocalPort $pi.name
        if (-not $listeners.ContainsKey($key)) { $listeners[$key] = @{ s = $l; proto = $proto; pi = $pi } }
    }
    if ($null -eq $State['listen_baseline']) {
        $State['listen_baseline'] = [string[]]@($listeners.Keys | Sort-Object)
        Write-AgentLog "baseline created with $($listeners.Count) listeners"
    }
    $baseline = @($State['listen_baseline'])
    $autoAccepted = @()
    foreach ($key in ($listeners.Keys | Sort-Object)) {
        $x = $listeners[$key]; $l = $x.s; $pi = $x.pi
        $t = Get-ProcessTrust $l.OwningProcess $pi
        $exposed = -not (Test-LocalAddr $l.LocalAddress) -or $l.LocalAddress -in @('0.0.0.0', '::')
        $ev = Merge-Hash @{ port = [int]$l.LocalPort; protocol = $x.proto; bind = "$($l.LocalAddress)"; process = $pi.name; pid = [int]$l.OwningProcess; exe = $pi.path; cmdline = $pi.cmdline } (Get-TrustEvidence $t)
        $sug = @()
        if ($pi.path -and $t.trust -in 'masquerade', 'unsigned', 'bad_signature') {
            $sug += Sug 'quarantine_file' @{ pid = [int]$l.OwningProcess; name = $pi.name; path = $pi.path } "Quarantine $($pi.name).exe (kill + move file, restorable)"
        }
        if ($pi.path -and $t.trust -notin 'masquerade', 'lolbin') { $sug += Sug 'allow_process' @{ name = $pi.name; path = $pi.path } "Trust $($pi.name).exe ($(if ($t.signer) { "pin signer '$($t.signer)'" } else { 'pin SHA256' }))" }
        if ($exposed) { $sug += Sug 'block_port' @{ port = [int]$l.LocalPort; protocol = $x.proto } "Block inbound $($x.proto)/$($l.LocalPort) at firewall" }
        if ($l.OwningProcess -gt 4) { $sug += Sug 'kill_process' @{ pid = [int]$l.OwningProcess; name = $pi.name } "Kill $($pi.name) (pid $($l.OwningProcess))" }

        if ($baseline -contains $key) {
            # Already-known port, but is the process behind it still authentic?
            if ($t.trust -in 'unsigned', 'bad_signature', 'lolbin') {
                Add-Alert 'untrusted_listener' $(if ($exposed -and $t.trust -ne 'unsigned') { 'high' } elseif ($exposed) { 'medium' } else { 'low' }) `
                    "untrusted:${key}:$($pi.path.ToLower())" ("{0}/{1} served by {2}: {3}" -f $x.proto.ToUpper(), $l.LocalPort, $pi.name, $t.trust.Replace('_', ' ')) `
                    "$($t.reason). Verify the file (hash/publisher), then trust or remove it." $ev $sug -Condition
            }
            continue
        }
        if ($Trusted -contains $t.trust) {
            $autoAccepted += $key
            Write-AgentLog "auto-accepted listener $key ($($pi.name), $($t.reason))"
            continue
        }
        $sev = switch ($t.trust) {
            'masquerade' { 'critical' }
            'bad_signature' { 'critical' }
            'lolbin' { 'high' }
            'unsigned' { if ($exposed) { 'high' } else { 'medium' } }
            'signed' { if ($exposed) { 'medium' } else { 'low' } }
            default { if ($exposed) { 'high' } else { 'low' } }   # unknown
        }
        if ($pi.path -match '\\(Temp|AppData|Downloads|Users\\Public|ProgramData)\\' -and $t.trust -ne 'signed') { $sev = 'critical' }
        $sug = @((Sug 'accept_listener' @{ port = [int]$l.LocalPort; protocol = $x.proto } 'Accept this port only (keep checking the process)')) + $sug
        Add-Alert 'new_listener' $sev "listener:$key" ("New {0} listener on port {1} ({2}, {3})" -f $x.proto.ToUpper(), $l.LocalPort, $pi.name, $t.trust.Replace('_', ' ')) `
            "Bound to $($l.LocalAddress). Not in this host's baseline. $($t.reason)." $ev $sug -Condition
    }
    if ($autoAccepted) { $State['listen_baseline'] = [string[]]@(@($State['listen_baseline']) + $autoAccepted | Sort-Object -Unique) }

    $susp = @($cfg.suspicious_ports | ForEach-Object { [int]$_ })
    $bad = @()
    if ($cfg.blocklist_file -and (Test-Path $cfg.blocklist_file -ErrorAction SilentlyContinue)) {
        $bad = @(Get-Content $cfg.blocklist_file | ForEach-Object { ($_ -split '\s')[0] } | Where-Object { $_ -and -not $_.StartsWith('#') })
    }
    $perIp = @{}
    foreach ($c in $tcp | Where-Object { $_.State -in 'Established', 'SynReceived', 'SynSent' }) {
        $rip = "$($c.RemoteAddress)" -replace '^::ffff:', ''
        if ((Test-LocalAddr $rip) -or (Test-InList $rip $cfg.trusted_ips)) { continue }
        $perIp[$rip] = 1 + [int]$perIp[$rip]
        $isBad = $bad.Count -and (Test-InList $rip $bad)
        $isSusp = ($susp -contains [int]$c.RemotePort) -or ($susp -contains [int]$c.LocalPort)
        if (-not ($isBad -or $isSusp)) { continue }
        $pi = Get-ProcInfo $c.OwningProcess
        $ev = Merge-Hash @{ remote_ip = $rip; remote_port = [int]$c.RemotePort; local_port = [int]$c.LocalPort; process = $pi.name; pid = [int]$c.OwningProcess; exe = $pi.path; cmdline = $pi.cmdline } (Get-TrustEvidence (Get-ProcessTrust $c.OwningProcess $pi))
        $sug = @((Sug 'block_ip' @{ ip = $rip } "Block $rip"))
        if ($c.OwningProcess -gt 4) { $sug += Sug 'kill_process' @{ pid = [int]$c.OwningProcess; name = $pi.name } "Kill $($pi.name) (pid $($c.OwningProcess))" }
        if ($isBad) {
            Add-Alert 'blocklisted_ip' 'critical' "blocklist:$rip" "Connection with blocklisted IP $rip" "$($pi.name) (pid $($c.OwningProcess)) <-> ${rip}:$($c.RemotePort)" $ev $sug
        }
        if ($isSusp) {
            $port = if ($susp -contains [int]$c.RemotePort) { [int]$c.RemotePort } else { [int]$c.LocalPort }
            $ev.port = $port
            Add-Alert 'suspicious_port' 'high' "susp:${rip}:${port}:$($pi.name)" "Connection on suspicious port $port with $rip" `
                "Process $($pi.name); ports like $port are common for reverse shells / C2." $ev $sug
        }
    }
    foreach ($ip in $perIp.Keys) {
        if ($perIp[$ip] -ge $th.conn_per_ip) {
            Add-Alert 'connection_flood' 'medium' "flood:$ip" "$($perIp[$ip]) concurrent connections from $ip" '' @{ remote_ip = $ip; connections = $perIp[$ip] } @((Sug 'block_ip' @{ ip = $ip } "Block $ip"))
        }
    }
    return @{ tcp = $tcp; listeners = $listeners.Count; established = @($tcp | Where-Object State -eq 'Established').Count }
}

function Invoke-ProcessIntegrityRules {
    # Scans ALL running processes (not just network ones) for fake Windows system processes.
    $lsassCount = 0
    foreach ($procId in @($script:ProcTable.Keys)) {
        $pi = Get-ProcInfo $procId
        $n = $pi.name
        if (-not $n) { continue }
        $killSug = if ($procId -gt 4) { @((Sug 'kill_process' @{ pid = [int]$procId; name = $n } "Kill $n (pid $procId)")) } else { @() }
        if ($procId -gt 4 -and $pi.path -and -not ($pi.path -like "$SR\*")) {
            $killSug = @((Sug 'quarantine_file' @{ pid = [int]$procId; name = $n; path = $pi.path } "Quarantine $n.exe (kill + move file, restorable)")) + $killSug
        }
        if ($WinAllow.ContainsKey($n)) {
            if ($n -eq 'lsass') { $lsassCount++ }
            $t = Get-ProcessTrust $procId $pi
            if ($t.trust -eq 'masquerade') {
                Add-Alert 'process_masquerade' 'critical' "masq:${n}:$($pi.path.ToLower())" "Fake Windows process: $n.exe (pid $procId)" $t.reason `
                    (Merge-Hash @{ process = $n; pid = $procId; exe = $pi.path; cmdline = $pi.cmdline; parent_pid = $pi.ppid } (Get-TrustEvidence $t)) $killSug -Condition
                continue
            }
            $want = $ExpectedParent[$n]
            if ($want -and $t.trust -eq 'system') {
                $pp = $script:ProcTable[$pi.ppid]
                # skip if parent is gone or the PID was reused by a younger process
                if ($pp -and $pp.CreationDate -le $pi.created) {
                    $pn = $pp.Name -replace '\.exe$', ''
                    if ($want -notcontains $pn) {
                        Add-Alert 'process_masquerade' 'high' "parent:${n}:$pn" "$n.exe started by unexpected parent $pn.exe" `
                            "Genuine $n.exe is normally started by $($want -join '/').exe. An unusual parent can mean process injection or a launched decoy." `
                            @{ process = $n; pid = $procId; exe = $pi.path; parent = $pn; parent_pid = $pi.ppid; parent_exe = "$($pp.ExecutablePath)"; trust = $t.trust } $killSug -Condition
                    }
                }
            }
        } else {
            $look = Get-LookAlike $n
            if ($look) {
                $t = Get-ProcessTrust $procId $pi
                if ($t.trust -notin 'system', 'allowlisted') {   # even a signed binary renamed to 'scvhost' is suspicious
                    Add-Alert 'process_masquerade' 'high' "lookalike:${n}:$($pi.path.ToLower())" "'$n.exe' imitates Windows '$look.exe' (pid $procId)" `
                        "Process name is one character away from a core Windows process. $($t.reason)." `
                        (Merge-Hash @{ process = $n; pid = $procId; exe = $pi.path; cmdline = $pi.cmdline; imitates = $look } (Get-TrustEvidence $t)) $killSug -Condition
                }
            }
        }
    }
    if ($lsassCount -gt 1) {
        Add-Alert 'process_masquerade' 'critical' 'multiple_lsass' "$lsassCount lsass.exe processes running" 'There must be exactly one lsass.exe. Extra copies are a credential-theft indicator.' @{ count = $lsassCount } @() -Condition
    }
}

function Get-EventField($xml, [string]$name) {
    $n = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if ($n) { return "$($n.'#text')" } else { return '' }
}

function Invoke-AuthRules {
    $lastRec = [long]$State['auth_last_record']
    $since = if ($State['auth_last_time']) { [DateTimeOffset]::FromUnixTimeSeconds([long]$State['auth_last_time'] - 5).LocalDateTime } else { $null }
    $State['auth_last_time'] = $Now
    if (-not $since) {
        # first run: remember where we are, don't alert on history
        try { $State['auth_last_record'] = (Get-WinEvent -LogName Security -MaxEvents 1).RecordId } catch { }
        return
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4624; StartTime = $since } -MaxEvents 5000 -ErrorAction Stop |
                Where-Object { $_.RecordId -gt $lastRec } | Sort-Object RecordId)
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { Write-AgentLog "security log: $($_.Exception.Message)" }
        return
    }
    $win = [int]$th.auth_window_seconds
    $fails = @{}; $users = @{}
    if ($State['auth_fails']) { foreach ($k in $State['auth_fails'].Keys) { $fails[$k] = @($State['auth_fails'][$k] | Where-Object { $Now - $_ -lt $win }) } }
    if ($State['auth_users']) { foreach ($k in $State['auth_users'].Keys) { $users[$k] = @($State['auth_users'][$k]) } }
    $bf = @{}
    if ($State['bruteforcers']) { foreach ($k in $State['bruteforcers'].Keys) { if ($Now - $State['bruteforcers'][$k] -lt 86400) { $bf[$k] = $State['bruteforcers'][$k] } } }

    foreach ($e in $events) {
        $State['auth_last_record'] = $e.RecordId
        $x = [xml]$e.ToXml()
        $ip = Get-EventField $x 'IpAddress'
        if (-not $ip -or $ip -eq '-' -or (Test-LocalAddr $ip)) { continue }
        $user = Get-EventField $x 'TargetUserName'
        $ltype = Get-EventField $x 'LogonType'
        if ($e.Id -eq 4625) {
            $fails[$ip] = @($fails[$ip]) + $Now | Where-Object { $_ }
            if (-not $users[$ip]) { $users[$ip] = @() }
            if ($users[$ip] -notcontains $user -and $users[$ip].Count -lt 20) { $users[$ip] = @($users[$ip]) + $user }
        } elseif ($bf.ContainsKey($ip) -and $ltype -in '3', '10') {
            Add-Alert 'login_after_bruteforce' 'critical' "login_after_bf:${ip}:$user" "Successful logon for '$user' from brute-forcing IP $ip" `
                "Logon type $ltype ($(if ($ltype -eq '10') {'RDP'} else {'network'})). This IP had many failed attempts earlier." `
                @{ remote_ip = $ip; user = $user; logon_type = $ltype; record_id = $e.RecordId } @((Sug 'block_ip' @{ ip = $ip } "Block $ip"))
        }
    }
    foreach ($ip in @($fails.Keys)) {
        $n = @($fails[$ip]).Count
        if ($n -eq 0) { $fails.Remove($ip); $users.Remove($ip); continue }
        if ($n -ge $th.auth_failures -and -not (Test-InList $ip $cfg.trusted_ips)) {
            $bf[$ip] = $Now
            Add-Alert 'auth_bruteforce' 'high' "bruteforce:logon:$ip" "Logon brute force from $ip ($n failures)" `
                "$n failed logons (RDP/SMB/network) in the last $([int]($win / 60)) min." `
                @{ remote_ip = $ip; failures = $n; usernames = @($users[$ip]); service = 'windows-logon' } @((Sug 'block_ip' @{ ip = $ip } "Block $ip"))
        }
    }
    $State['auth_fails'] = $fails; $State['auth_users'] = $users; $State['bruteforcers'] = $bf
}

function Invoke-ScanRules($tcp) {
    $hits = @{}
    $logFile = (Get-NetFirewallProfile -Profile Public).LogFileName
    if ($logFile) { $logFile = [Environment]::ExpandEnvironmentVariables($logFile) }
    if ($logFile -and (Test-Path $logFile)) {
        $fi = Get-Item $logFile
        $pos = [long]$State['fwlog_offset']
        if ($null -eq $State['fwlog_offset']) { $pos = $fi.Length }
        if ($fi.Length -lt $pos) { $pos = 0 }  # rotated
        try {
            $fs = [IO.File]::Open($logFile, 'Open', 'Read', 'ReadWrite')
            [void]$fs.Seek($pos, 'Begin')
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $f = $line -split ' '
                if ($f.Count -ge 8 -and $f[2] -eq 'DROP' -and -not (Test-LocalAddr $f[4])) {
                    if (-not $hits[$f[4]]) { $hits[$f[4]] = New-Object System.Collections.Generic.HashSet[int] }
                    [void]$hits[$f[4]].Add([int]$f[7])
                }
            }
            $State['fwlog_offset'] = $fs.Position
            $sr.Close()
        } catch { Write-AgentLog "firewall log: $($_.Exception.Message)" }
    }
    foreach ($c in $tcp | Where-Object State -eq 'SynReceived') {
        $ip = "$($c.RemoteAddress)"
        if (Test-LocalAddr $ip) { continue }
        if (-not $hits[$ip]) { $hits[$ip] = New-Object System.Collections.Generic.HashSet[int] }
        [void]$hits[$ip].Add([int]$c.LocalPort)
    }
    foreach ($ip in $hits.Keys) {
        if ($hits[$ip].Count -ge $th.port_scan_ports -and -not (Test-InList $ip $cfg.trusted_ips)) {
            $ports = @($hits[$ip] | Sort-Object | Select-Object -First 50)
            Add-Alert 'port_scan' 'medium' "scan:$ip" "Port scan from $ip ($($hits[$ip].Count) ports)" '' @{ remote_ip = $ip; ports = $ports; distinct_ports = $hits[$ip].Count } @((Sug 'block_ip' @{ ip = $ip } "Block $ip"))
        }
    }
}

function Invoke-ResourceRules {
    $m = @{}
    $m.cpu_pct = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $os = Get-CimInstance Win32_OperatingSystem
    $m.mem_pct = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize), 1)
    $worst = 0; $worstDrive = ''
    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') {
        if ($d.Size -gt 0) { $p = 100 * (1 - $d.FreeSpace / $d.Size); if ($p -gt $worst) { $worst = $p; $worstDrive = $d.DeviceID } }
    }
    $m.disk_pct = [math]::Round($worst, 1)
    try {
        $stats = Get-NetAdapterStatistics -ErrorAction Stop
        $rx = ($stats | Measure-Object ReceivedBytes -Sum).Sum; $tx = ($stats | Measure-Object SentBytes -Sum).Sum
        $t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        $prev = $State['net_prev']
        $State['net_prev'] = @($t, $rx, $tx)
        if ($prev -and $t -gt $prev[0] -and $rx -ge $prev[1] -and $tx -ge $prev[2]) {
            $dt = $t - $prev[0]
            $m.rx_mbps = [math]::Round(($rx - $prev[1]) * 8 / $dt / 1e6, 2)
            $m.tx_mbps = [math]::Round(($tx - $prev[2]) * 8 / $dt / 1e6, 2)
            foreach ($d in 'rx', 'tx') {
                if ($m["${d}_mbps"] -ge $th["${d}_mbps"]) {
                    Add-Alert 'bandwidth_spike' 'medium' "bw:$d" ('{0} throughput {1:N0} Mbps' -f $(if ($d -eq 'rx') { 'Inbound' } else { 'Outbound' }), $m["${d}_mbps"]) `
                        "Threshold $($th["${d}_mbps"]) Mbps." @{ direction = $d; mbps = $m["${d}_mbps"] } @() -Condition
                }
            }
        }
    } catch { }
    $hot = if ($m.cpu_pct -ge $th.cpu_pct) { 1 + [int]$State['cpu_hot'] } else { 0 }
    $State['cpu_hot'] = $hot
    if ($hot -ge $th.cpu_cycles) {
        $top = @(Get-Process | Sort-Object CPU -Descending | Select-Object -First 5)
        $sug = @(); if ($top) { $sug += Sug 'kill_process' @{ pid = [int]$top[0].Id; name = $top[0].ProcessName } "Kill $($top[0].ProcessName) (pid $($top[0].Id))" }
        Add-Alert 'resource_pressure' 'medium' 'res:cpu' "CPU at $($m.cpu_pct)% for $hot cycles" 'Unexpected sustained CPU can indicate a crypto-miner.' `
            @{ cpu_pct = $m.cpu_pct; top_processes = @($top | ForEach-Object { '{0} {1} cpu={2:N0}s' -f $_.Id, $_.ProcessName, $_.CPU }) } $sug -Condition
    }
    if ($m.mem_pct -ge $th.mem_pct) { Add-Alert 'resource_pressure' 'medium' 'res:mem' "Memory at $($m.mem_pct)%" '' @{ mem_pct = $m.mem_pct } @() -Condition }
    if ($m.disk_pct -ge $th.disk_pct) {
        Add-Alert 'resource_pressure' $(if ($m.disk_pct -ge 97) { 'high' } else { 'medium' }) 'res:disk' "Disk $worstDrive at $($m.disk_pct)%" `
            'Full disks stop logging and break services.' @{ drive = $worstDrive; disk_pct = $m.disk_pct } @() -Condition
    }
    return $m
}

function Invoke-SecurityStateRules {
    $off = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled })
    if ($off) {
        Add-Alert 'firewall_disabled' 'critical' 'firewall_off' ("Windows Firewall off for: " + (($off | ForEach-Object Name) -join ', ')) '' @{ profiles = @($off | ForEach-Object Name) } `
            @((Sug 'harden_fix' @{ check_id = 'firewall_profiles' } 'Enable firewall (RDP/WinRM kept reachable)')) -Condition
    }
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp -and $mp.AMServiceEnabled -and -not $mp.RealTimeProtectionEnabled) {
        Add-Alert 'defender_disabled' 'high' 'defender_rtp_off' 'Defender real-time protection is OFF' '' @{ antivirus_enabled = $mp.AntivirusEnabled } `
            @((Sug 'harden_fix' @{ check_id = 'defender_realtime' } 'Turn real-time protection back on')) -Condition
    }
}

$script:HardeningSummary = $null
function Invoke-HardenScript([string[]]$HardenArgs) {
    # Runs Harden-Server.ps1 in a child process; JSON goes to a file because
    # powershell.exe -File mangles a lone '-' argument.
    $jf = Join-Path $cfg.state_dir ("harden-{0}.json" -f [guid]::NewGuid())
    $log = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cfg.harden_script @HardenArgs -Json $jf 2>&1 | Out-String
    $rep = $null
    try { $rep = Get-Content $jf -Raw -ErrorAction Stop | ConvertFrom-Json } catch { Write-AgentLog "hardening produced no JSON: $($log.Trim())" }
    Remove-Item $jf -ErrorAction SilentlyContinue
    if ($rep) { $rep | Add-Member -NotePropertyName log -NotePropertyValue $log -Force }
    return $rep
}
function Invoke-HardeningRules([switch]$Force) {
    $script_ = $cfg.harden_script
    $due = $Force -or ($Now - [long]$State['harden_last'] -ge [int]$cfg.hardening_interval_minutes * 60)
    if ($due -and $script_ -and (Test-Path $script_)) {
        $rep = Invoke-HardenScript @('-Mode', 'Audit')
        if ($rep) {
            $State['harden_last'] = $Now
            $res = @($rep.results)
            $app = @($res | Where-Object status -ne 'na')
            $script:HardeningSummary = @{ total = $app.Count; passed = @($app | Where-Object status -eq 'pass').Count; ts = $Now }
            $fails = @($res | Where-Object status -eq 'fail' | ForEach-Object { @{ id = $_.id; title = $_.title; severity = $_.severity; detail = $_.detail; fixable = $_.fixable
                        change = "$($_.change)"; risk = "$($_.risk)"; reboot = [bool]$_.reboot } })
            $State['harden_fails'] = $fails
            foreach ($r in $fails) {
                $sug = @()
                if ($r.fixable) { $sug += Sug 'harden_fix' @{ check_id = $r.id } "Apply fix$(if ($r.reboot) { ' (reboot needed)' })" }
                $ev = @{ check_id = $r.id; current = $r.detail }
                if ($r.change) { $ev.fix_changes = $r.change }
                if ($r.risk) { $ev.fix_risk = $r.risk }
                if ($r.fixable) { $ev.fix_reboot = $(if ($r.reboot) { 'yes' } else { 'no' }) }
                Add-Alert 'hardening_drift' $r.severity "harden:$($r.id)" "Hardening: $($r.title)" $r.detail $ev $sug -Condition
            }
            return
        }
    }
    foreach ($r in @($State['harden_fails'])) { if ($r) { [void]$Conditions.Add("harden:$($r.id)") } }
}

# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------
$Protected = @('system', 'idle', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'lsaiso', 'registry', 'memory compression')

function Get-ServerIp {
    try { $h = ([Uri]$cfg.server_url).Host; return ([Net.Dns]::GetHostAddresses($h) | Select-Object -First 1).IPAddressToString } catch { return $null }
}
function Get-RdpPort { $p = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).PortNumber; if ($p) { $p } else { 3389 } }

$Supported = @('block_ip', 'unblock_ip', 'block_port', 'unblock_port', 'kill_process', 'quarantine_file', 'restore_quarantine',
    'allow_process', 'harden_fix', 'harden_restore', 'run_hardening_audit', 'accept_listener')
$QuarantineDir = Join-Path $cfg.state_dir 'quarantine'
$HardenBackupRoot = Join-Path $env:ProgramData 'NetGuard\hardening-backups'

function Remove-ExpiredBlocks {
    $tb = $State['timed_blocks']
    if (-not $tb) { return }
    $keep = @{}
    foreach ($ip in @($tb.Keys)) {
        if ([long]$tb[$ip] -le $Now) {
            Get-NetFirewallRule -DisplayName "NetGuard-Block-*-$ip" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            Write-AgentLog "timed block for $ip expired - rules removed"
        } else { $keep[$ip] = $tb[$ip] }
    }
    $State['timed_blocks'] = $keep
}

function Invoke-Command_($cmd) {
    $script:Undo = $null
    # Optional per-host restriction of what the dashboard may do here (e.g. a lab/test machine).
    if ($null -ne $cfg.allowed_actions -and @($cfg.allowed_actions) -notcontains $cmd.action) {
        throw "action '$($cmd.action)' is disabled on this host by allowed_actions in the agent config"
    }
    $p = ConvertTo-HashtableDeep $cmd.params
    switch ($cmd.action) {
        'block_ip' {
            $ip = "$($p.ip)"; $base = ($ip -split '/')[0]
            [void][Net.IPAddress]::Parse($base)
            if (Test-LocalAddr $base) { throw 'refusing loopback' }
            if (Test-InList $base $cfg.trusted_ips) { throw "$ip is in trusted_ips; refusing" }
            $srv = Get-ServerIp
            if ($srv -and (Test-InNet $srv $ip)) { throw "$ip would cut the agent off from the dashboard ($srv)" }
            $rdp = Get-RdpPort
            $live = Get-NetTCPConnection -State Established -LocalPort $rdp, 5985, 5986 -ErrorAction SilentlyContinue | Where-Object { Test-InNet "$($_.RemoteAddress)" $ip }
            if ($live) { throw "an RDP/WinRM session from $($live[0].RemoteAddress) is active (could be you). Block manually if intended." }
            New-NetFirewallRule -DisplayName "NetGuard-Block-In-$ip" -Direction Inbound -RemoteAddress $ip -Action Block -Description 'NetGuard dashboard action' | Out-Null
            New-NetFirewallRule -DisplayName "NetGuard-Block-Out-$ip" -Direction Outbound -RemoteAddress $ip -Action Block -Description 'NetGuard dashboard action' | Out-Null
            $script:Undo = @{ action = 'unblock_ip'; params = @{ ip = $ip }; label = "Unblock $ip" }
            $hours = [int]$p.hours
            if ($hours -gt 0) {
                if (-not $State['timed_blocks']) { $State['timed_blocks'] = @{} }
                $State['timed_blocks'][$ip] = $Now + $hours * 3600
                return "blocked $ip inbound+outbound for $hours h (removed automatically after that)"
            }
            return "blocked $ip inbound+outbound permanently (rules NetGuard-Block-In/Out-$ip)"
        }
        'unblock_ip' {
            $ip = "$($p.ip)"
            $r = @(Get-NetFirewallRule -DisplayName "NetGuard-Block-*-$ip" -ErrorAction SilentlyContinue)
            $r | Remove-NetFirewallRule
            if ($State['timed_blocks']) { $State['timed_blocks'].Remove($ip) }
            return "removed $($r.Count) rule(s) for $ip"
        }
        'block_port' {
            $port = [int]$p.port; $proto = "$($p.protocol)".ToUpper()
            if ($proto -notin 'TCP', 'UDP' -or $port -lt 1 -or $port -gt 65535) { throw 'bad port/protocol' }
            if ($proto -eq 'TCP' -and $port -in @((Get-RdpPort), 5985, 5986)) { throw "refusing to block remote-management port $port" }
            New-NetFirewallRule -DisplayName "NetGuard-BlockPort-$proto-$port" -Direction Inbound -Protocol $proto -LocalPort $port -Action Block -Description 'NetGuard dashboard action' | Out-Null
            $script:Undo = @{ action = 'unblock_port'; params = @{ port = $port; protocol = $proto.ToLower() }; label = "Unblock $proto/$port" }
            return "blocked inbound $proto/$port (other machines can no longer connect to it; local use unaffected)"
        }
        'unblock_port' {
            $port = [int]$p.port; $proto = "$($p.protocol)".ToUpper()
            $r = @(Get-NetFirewallRule -DisplayName "NetGuard-BlockPort-$proto-$port" -ErrorAction SilentlyContinue)
            $r | Remove-NetFirewallRule
            return "removed $($r.Count) block rule(s) for $proto/$port"
        }
        'quarantine_file' {
            $procId = [int]$p.pid; $name = "$($p.name)"; $path = "$($p.path)"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "file not found: $path" }
            $sig = Get-SigInfo $path
            if ($sig.microsoft -and $path -like "$SR\*") { throw "refusing: $path is a Microsoft-signed file in the Windows folder" }
            if (@(@($cfg.process_allowlist) + @($State['process_allowlist']) | Where-Object { $_ -and $_.path -eq $path }).Count) { throw "refusing: $path is on the trusted list" }
            $sha = Get-Sha256 $path
            # stop every process running this exact file (malware often runs several copies)
            $killed = @()
            foreach ($proc in Get-CimInstance Win32_Process) {
                $pp = "$($proc.ExecutablePath)"; if (-not $pp) { try { $pp = "$([NgProc]::ImagePath([int]$proc.ProcessId))" } catch { } }
                if ($pp -and $pp -eq $path -and $proc.ProcessId -gt 4) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue; $killed += $proc.ProcessId }
            }
            Start-Sleep -Milliseconds 500
            New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
            $qid = '{0}-{1}' -f $sha.Substring(0, 12), $Now
            $dest = Join-Path $QuarantineDir "$qid.bin"
            $moved = $false
            foreach ($i in 1..5) { try { Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop; $moved = $true; break } catch { Start-Sleep -Milliseconds 500 } }
            if (-not $moved) { throw "killed pid(s) $($killed -join ', ') but could not move $path (still locked?)" }
            @{ id = $qid; name = $name; original_path = $path; sha256 = $sha; signer = $sig.signer; signature = $sig.status; quarantined = $Now } |
                ConvertTo-Json | Set-Content -Path (Join-Path $QuarantineDir "$qid.json") -Encoding UTF8
            $script:Undo = @{ action = 'restore_quarantine'; params = @{ id = $qid }; label = "Restore $name.exe to its original folder" }
            return "killed pid(s) $($killed -join ', '); moved $path to quarantine as $qid.bin (SHA256 $sha). It can no longer run. Restore it from the action history if this was a mistake."
        }
        'restore_quarantine' {
            $qid = "$($p.id)"
            if ($qid -notmatch '^[A-Fa-f0-9]{12}-\d+$') { throw 'bad quarantine id' }
            $meta = Get-Content (Join-Path $QuarantineDir "$qid.json") -Raw | ConvertFrom-Json
            if (Test-Path -LiteralPath $meta.original_path) { throw "a file already exists at $($meta.original_path); not overwriting" }
            New-Item -ItemType Directory -Path (Split-Path $meta.original_path) -Force | Out-Null
            Move-Item -LiteralPath (Join-Path $QuarantineDir "$qid.bin") -Destination $meta.original_path
            Remove-Item (Join-Path $QuarantineDir "$qid.json") -Force
            return "restored $($meta.original_path) (it is not started again automatically)"
        }
        'kill_process' {
            $procId = [int]$p.pid; $name = "$($p.name)"
            if ($procId -le 4) { throw "refusing to kill pid $procId" }
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if (-not $proc) { return "process $procId already gone" }
            if ($proc.ProcessName -ne $name) { throw "pid $procId is now '$($proc.ProcessName)', not '$name'; refusing (pid reused?)" }
            $ProcCache.Remove($procId); $TrustCache.Remove($procId)
            $pi = Get-ProcInfo $procId
            $t = Get-ProcessTrust $procId $pi
            if ($Protected -contains $proc.ProcessName.ToLower() -or $WinAllow.ContainsKey($name)) {
                # Only an IMPOSTOR of a system process may be killed; the genuine one would crash/BSOD the server.
                if ($t.trust -eq 'system') { throw "refusing: $name (pid $procId) is the genuine Windows binary ($($t.reason))" }
                if ($t.trust -eq 'unknown') { throw "refusing: cannot verify $name (pid $procId) - $($t.reason)" }
            }
            Stop-Process -Id $procId -Force
            return "killed $name (pid $procId, $($pi.path), trust=$($t.trust), sha256=$($t.sha256))"
        }
        'allow_process' {
            $name = "$($p.name)"; $path = "$($p.path)"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "file not found: $path" }
            if ($WinAllow.ContainsKey($name)) { throw "$name is a core Windows name; it is verified by path + Microsoft signature and cannot be allowlisted manually" }
            if ($LolBins -contains $name) { throw "$name is a commonly-abused system tool; allowlisting it would trust every script it runs. Use 'Accept this port only' instead." }
            $sig = Get-SigInfo $path
            $entry = @{ name = $name; path = $path; added = $Now }
            if ($sig.status -eq 'Valid') { $entry.signer = $sig.signer; $how = "pinned to signer '$($sig.signer)' (thumbprint $($sig.thumbprint))" }
            else { $entry.sha256 = Get-Sha256 $path; $how = "signature '$($sig.status)', so pinned to SHA256 $($entry.sha256) - it will alert again if the file changes" }
            $State['process_allowlist'] = @(@($State['process_allowlist'] | Where-Object { $_ -and -not ($_.name -eq $name -and $_.path -eq $path) }) + $entry)
            return "allowlisted $name at $path; $how. Its listeners are accepted on the next cycle."
        }
        'accept_listener' {
            $port = [int]$p.port; $proto = "$($p.protocol)".ToLower()
            $keys = @("${proto}:$port")
            if ($port -ge 49152) {
                $owner = if ($proto -eq 'tcp') { (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess } else { (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess }
                if ($owner) { $keys = @(Get-ListenerKey $proto $port (Get-ProcInfo $owner).name) }
            }
            $State['listen_baseline'] = [string[]]@(@($State['listen_baseline']) + $keys | Sort-Object -Unique)
            return "added $($keys -join ', ') to listener baseline"
        }
        'harden_fix' {
            $id = "$($p.check_id)"
            if ($id -notmatch '^[A-Za-z0-9_.\-]+$') { throw 'bad check id' }
            $rep = Invoke-HardenScript @('-Mode', 'Apply', '-Yes', '-Only', $id)
            $State['harden_last'] = 0
            $st = 'unknown'; $detail = ''; $log = ''
            if ($rep) { $r = @($rep.results)[0]; if ($r) { $st = $r.status; $detail = $r.detail }; $log = $rep.log }
            if ($st -notin 'fixed', 'pass') { throw "check $id -> $st. $detail`n$log" }
            if ($rep.backup_dir) { $script:Undo = @{ action = 'harden_restore'; params = @{ backup = "$($rep.backup_dir)" }; label = "Undo: restore previous settings" } }
            return "check $id -> $st. $detail`n$log"
        }
        'harden_restore' {
            $b = [IO.Path]::GetFullPath("$($p.backup)")
            if (-not $b.StartsWith($HardenBackupRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "backup must be under $HardenBackupRoot" }
            if (-not (Test-Path (Join-Path $b 'rollback.json'))) { throw "no rollback.json in $b" }
            $log = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cfg.harden_script -Restore $b 2>&1 | Out-String
            $State['harden_last'] = 0
            return "restored settings from $b`n$($log.Trim())"
        }
        'run_hardening_audit' { $State['harden_last'] = 0; return 'audit scheduled for this cycle' }
        default { throw "unsupported action $($cmd.action)" }
    }
}

# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not $cfg.verify_tls) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
function Send-Json([string]$path, $payload) {
    $body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payload -Depth 8 -Compress))
    return Invoke-RestMethod -Uri ($cfg.server_url.TrimEnd('/') + $path) -Method Post -Body $body -ContentType 'application/json; charset=utf-8' `
        -Headers @{ 'X-Agent-Token' = $(if ($State['host_token']) { $State['host_token'] } else { $cfg.agent_token }) } -UserAgent "netguard-agent/$AgentVersion" -TimeoutSec 30 -UseBasicParsing
}

# ---------------------------------------------------------------------------
# Command signatures (ECDSA P-256 / SHA-256, verified with Windows CNG)
# ---------------------------------------------------------------------------
function Get-DashboardKey($resp) {
    $offered = "$($resp.command_public_key)"
    $pinned = if ($cfg.command_public_key) { "$($cfg.command_public_key)" } else { "$($State['command_key'])" }
    if (-not $pinned -and $offered) {
        $State['command_key'] = $pinned = $offered
        Write-AgentLog "pinned the dashboard's command-signing key (first contact)"
    }
    if ($pinned -and $offered -and $offered -ne $pinned) {
        Write-AgentLog "WARNING: dashboard offered a DIFFERENT command key than the pinned one - refusing all commands. If the dashboard was reinstalled on purpose, remove command_key from agent-state.json"
        return $null
    }
    return $pinned
}
function Test-CommandSignature([string]$payload, [string]$sigB64, [string]$keyB64) {
    try {
        $pub = [Convert]::FromBase64String($keyB64)
        if ($pub.Length -ne 64) { return $false }
        $blob = New-Object byte[] 72
        [BitConverter]::GetBytes([uint32]0x31534345).CopyTo($blob, 0)    # BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        [BitConverter]::GetBytes([uint32]32).CopyTo($blob, 4)
        [Array]::Copy($pub, 0, $blob, 8, 64)
        $key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $ec = New-Object Security.Cryptography.ECDsaCng($key)
        $ec.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256
        return $ec.VerifyData([Text.Encoding]::UTF8.GetBytes($payload), [Convert]::FromBase64String($sigB64))
    } catch { return $false }
}
function Confirm-Command($c, [string]$keyB64) {
    if (-not $keyB64) { throw 'no trusted dashboard key - command refused' }
    if (-not $c.envelope -or -not $c.sig) { throw 'unsigned command refused' }
    if (-not (Test-CommandSignature "$($c.envelope)" "$($c.sig)" $keyB64)) { throw 'invalid signature - command refused' }
    $e = "$($c.envelope)" | ConvertFrom-Json
    if ("$($e.host)" -ne $HostName) { throw "command is for $($e.host), not this server - refused" }
    if ([long]$e.id -ne [long]$c.id) { throw 'command id mismatch - refused' }
    if ([long]$e.expires -lt $Now - 300 -or [long]$e.issued -gt $Now + 300) { throw 'command expired or from the future (check the clock) - refused' }
    $seen = @($State['seen_cmds'] | Where-Object { $null -ne $_ })
    if ($seen -contains [long]$e.id) { throw 'command already executed (replay) - refused' }
    $State['seen_cmds'] = @(@($seen + [long]$e.id) | Select-Object -Last 500)
    return [pscustomobject]@{ id = $e.id; action = "$($e.action)"; params = $e.params }
}

# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------
function Invoke-Cycle([switch]$ForceAudit) {
    $Alerts.Clear(); $Conditions.Clear(); $script:HardeningSummary = $null
    try { Remove-ExpiredBlocks } catch { Write-AgentLog "timed block cleanup: $($_.Exception.Message)" }
    Update-ProcTable
    $sock = Invoke-SocketRules
    foreach ($rule in @({ Invoke-ProcessIntegrityRules }, { Invoke-AuthRules }, { Invoke-ScanRules $sock.tcp }, { Invoke-SecurityStateRules })) {
        try { & $rule } catch { Write-AgentLog "rule error: $($_.Exception.Message)" }
    }
    $metrics = Invoke-ResourceRules
    $metrics.listening = $sock.listeners; $metrics.established = $sock.established
    Invoke-HardeningRules -Force:$ForceAudit

    $prev = @($State['conditions'] | Where-Object { $_ })
    $cleared = @($prev | Where-Object { -not $Conditions.Contains($_) })
    $osName = (Get-CimInstance Win32_OperatingSystem).Caption
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
    $report = @{ host = $HostName; os = $osName; ip = "$ip"; agent_version = $AgentVersion; metrics = $metrics
        alerts = @($Alerts); cleared = $cleared }
    if ($script:HardeningSummary) { $report.hardening = $script:HardeningSummary }
    $report.capabilities = @{ supported = $Supported; allowed_actions = $(if ($null -ne $cfg.allowed_actions) { @($cfg.allowed_actions) } else { $null }) }

    if ($DryRun) { ConvertTo-Json -InputObject $report -Depth 8; Save-State; return }
    try { $resp = Send-Json '/api/agent/report' $report }
    catch { Write-AgentLog "report failed: $($_.Exception.Message)"; Save-State; return }
    $State['conditions'] = [string[]]@($Conditions)
    if ($resp.agent_token) {
        $State['host_token'] = "$($resp.agent_token)"
        Write-AgentLog "received this server's own agent key; the join token is no longer used"
    }
    $key = Get-DashboardKey $resp
    Save-State      # persist the key immediately
    $rerun = $false
    foreach ($c in @($resp.commands)) {
        if (-not $c) { continue }
        try { $verified = Confirm-Command $c $key; $out = Invoke-Command_ $verified; $st = 'done' } catch { $out = "$($_.Exception.Message)"; $st = 'failed'; $script:Undo = $null }
        Write-AgentLog "command $($c.id) $($c.action) -> $st"
        if ($c.action -in 'harden_fix', 'run_hardening_audit') { $rerun = $true }
        $result = @{ host = $HostName; id = $c.id; status = $st; output = "$out" }
        if ($script:Undo) { $result.undo = $script:Undo }
        try { [void](Send-Json '/api/agent/command_result' $result) }
        catch { Write-AgentLog "could not report command result: $($_.Exception.Message)" }
    }
    Save-State
    if ($rerun) { Invoke-Cycle -ForceAudit }
}

# Single instance guard (scheduled task may overlap on a slow cycle)
$mutex = New-Object Threading.Mutex($false, 'Global\NetGuardAgent')
if (-not $mutex.WaitOne(0)) { Write-AgentLog 'previous cycle still running, skipping'; exit 0 }
try { Invoke-Cycle } catch { Write-AgentLog "cycle error: $($_.Exception.Message)"; throw } finally { $mutex.ReleaseMutex() }
exit 0
