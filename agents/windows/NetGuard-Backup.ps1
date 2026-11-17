<#
.SYNOPSIS
    NetGuard backup runner (Windows). Started by the agent in its own process:
      NetGuard-Backup.ps1 -JobFile F -Mode backup|test|restore [-Archive NAME] [-Target DIR] -ResultFile R -RunRef ID -HostName H -StateDir D

.DESCRIPTION
    Archive format NGBK1 - identical to the Linux runner, decrypt anywhere with tools/ng-decrypt.py:
      "NGBK1" | "Salted__" + 8-byte salt + AES-256-CBC ciphertext | HMAC-SHA256 tag (32 bytes)
      passphrase = hex(HMAC-SHA256(jobKey, "enc")); AES key+IV = PBKDF2-HMAC-SHA256(passphrase, salt, 1, 48 bytes)
      tag = HMAC-SHA256(HMAC-SHA256(jobKey, "mac"), everything before the tag)
#>
[CmdletBinding()]
param(
    [string]$JobFile = '',
    [ValidateSet('backup', 'test', 'restore')] [string]$Mode = 'backup',
    [string]$Archive = '',
    [string]$Target = '',
    [string]$ResultFile = '',
    [string]$RunRef = ([guid]::NewGuid().ToString()),
    [string]$HostName = $env:COMPUTERNAME,
    [string]$StateDir = (Join-Path $env:ProgramData 'NetGuard'),
    [switch]$LibOnly      # dot-source the functions only (tests)
)
$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$script:Log = New-Object System.Collections.Generic.List[string]
function Write-RunLog([string]$m) { $script:Log.Add(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) }
$Utf8 = New-Object Text.UTF8Encoding($false)
$Magic = [Text.Encoding]::ASCII.GetBytes('NGBK1')

# ---------------------------------------------------------------------------
# Crypto helpers (NGBK1)
# ---------------------------------------------------------------------------
function Get-Hmac([byte[]]$key, [byte[]]$data) { $h = New-Object Security.Cryptography.HMACSHA256(, $key); try { return $h.ComputeHash($data) } finally { $h.Dispose() } }
function Get-SubKeys([byte[]]$key) {
    $enc = Get-Hmac $key ([Text.Encoding]::ASCII.GetBytes('enc'))
    $mac = Get-Hmac $key ([Text.Encoding]::ASCII.GetBytes('mac'))
    return @{ pass = [Text.Encoding]::ASCII.GetBytes((($enc | ForEach-Object { $_.ToString('x2') }) -join '')); mac = $mac }
}
function Get-KeyIv([byte[]]$pass, [byte[]]$salt) {
    # PBKDF2-HMAC-SHA256 with 1 iteration, 48 bytes: T1 || T2[0..15]
    $t1 = Get-Hmac $pass ($salt + [byte[]](0, 0, 0, 1))
    $t2 = Get-Hmac $pass ($salt + [byte[]](0, 0, 0, 2))
    return @{ key = $t1; iv = $t2[0..15] }
}
function New-Aes($k) {
    $a = New-Object Security.Cryptography.AesCryptoServiceProvider
    $a.Mode = 'CBC'; $a.Padding = 'PKCS7'; $a.KeySize = 256; $a.Key = $k.key; $a.IV = [byte[]]$k.iv
    return $a
}
function Protect-File([string]$src, [string]$dst, [byte[]]$jobKey) {
    $sk = Get-SubKeys $jobKey
    $salt = New-Object byte[] 8; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $aes = New-Aes (Get-KeyIv $sk.pass $salt)
    $out = [IO.File]::Open($dst, 'Create', 'ReadWrite', 'None')
    try {
        $out.Write($Magic, 0, $Magic.Length)
        $hdr = [Text.Encoding]::ASCII.GetBytes('Salted__') + $salt
        $out.Write($hdr, 0, $hdr.Length)
        $in = [IO.File]::OpenRead($src)
        $cs = New-Object Security.Cryptography.CryptoStream($out, $aes.CreateEncryptor(), 'Write')
        $in.CopyTo($cs, 1MB); $cs.FlushFinalBlock(); $in.Dispose()
        # tag over everything written so far
        $out.Position = 0
        $h = New-Object Security.Cryptography.HMACSHA256(, $sk.mac)
        $tag = $h.ComputeHash($out)
        $out.Seek(0, 'End') | Out-Null
        $out.Write($tag, 0, 32)
    } finally { $out.Dispose(); $aes.Dispose() }
}
function Unprotect-File([string]$src, [string]$dst, [byte[]]$jobKey) {
    $sk = Get-SubKeys $jobKey
    $fs = [IO.File]::OpenRead($src)
    try {
        $len = $fs.Length
        if ($len -lt 5 + 16 + 32) { throw 'file too small to be an NGBK1 archive' }
        $head = New-Object byte[] 21; [void]$fs.Read($head, 0, 21)
        if ([Text.Encoding]::ASCII.GetString($head, 0, 5) -ne 'NGBK1' -or [Text.Encoding]::ASCII.GetString($head, 5, 8) -ne 'Salted__') { throw 'not an NGBK1 archive' }
        $salt = $head[13..20]
        # 1) verify the tag over [0, len-32)
        $h = New-Object Security.Cryptography.HMACSHA256(, $sk.mac)
        $fs.Position = 0
        $buf = New-Object byte[] 1MB; $remaining = $len - 32
        while ($remaining -gt 0) { $n = $fs.Read($buf, 0, [Math]::Min($buf.Length, $remaining)); [void]$h.TransformBlock($buf, 0, $n, $null, 0); $remaining -= $n }
        [void]$h.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        $tag = New-Object byte[] 32; [void]$fs.Read($tag, 0, 32)
        $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($h.Hash[$i] -bxor $tag[$i]) }
        if ($diff -ne 0) { throw 'integrity check FAILED: wrong key, or the archive was damaged/tampered with' }
        # 2) decrypt the ciphertext region
        $aes = New-Aes (Get-KeyIv $sk.pass $salt)
        $dec = $aes.CreateDecryptor()
        $out = [IO.File]::Create($dst)
        try {
            $fs.Position = 21; $remaining = $len - 32 - 21
            $outBuf = New-Object byte[] (1MB + 32)
            while ($remaining -gt 0) {
                $want = [Math]::Min($buf.Length, $remaining); $n = $fs.Read($buf, 0, $want); $remaining -= $n
                if ($remaining -gt 0) { $w = $dec.TransformBlock($buf, 0, $n, $outBuf, 0); $out.Write($outBuf, 0, $w) }
                else { $last = $dec.TransformFinalBlock($buf, 0, $n); $out.Write($last, 0, $last.Length) }
            }
        } finally { $out.Dispose(); $aes.Dispose() }
    } finally { $fs.Dispose() }
}
function Get-Sha256Hex([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }

# ---------------------------------------------------------------------------
# S3 (AWS Signature V4)
# ---------------------------------------------------------------------------
$EmptyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
function ConvertTo-HexLower([byte[]]$b) { ($b | ForEach-Object { $_.ToString('x2') }) -join '' }
function Get-StrSha256([string]$s) { $sha = [Security.Cryptography.SHA256]::Create(); ConvertTo-HexLower ($sha.ComputeHash($Utf8.GetBytes($s))) }
function Get-HmacStr([byte[]]$k, [string]$s) { Get-Hmac $k ($Utf8.GetBytes($s)) }
function ConvertTo-UriEncoded([string]$s, [bool]$keepSlash) {
    $sb = New-Object Text.StringBuilder
    foreach ($byte in $Utf8.GetBytes($s)) {
        $c = [char]$byte
        if (($c -ge 'A' -and $c -le 'Z') -or ($c -ge 'a' -and $c -le 'z') -or ($c -ge '0' -and $c -le '9') -or '-_.~'.Contains($c) -or ($keepSlash -and $c -eq '/')) { [void]$sb.Append($c) }
        else { [void]$sb.Append('%' + $byte.ToString('X2')) }
    }
    $sb.ToString()
}
function Get-SigV4Headers([string]$method, [string]$url, [string]$region, [string]$ak, [string]$sk, [string]$payloadHash, [string]$amzDate = '', [hashtable]$extra = @{}) {
    $u = [Uri]$url
    if (-not $amzDate) { $amzDate = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') }
    $date = $amzDate.Substring(0, 8)
    $hdr = @{ 'host' = $u.Authority; 'x-amz-content-sha256' = $payloadHash; 'x-amz-date' = $amzDate }
    foreach ($k in $extra.Keys) { $hdr[$k.ToLower()] = "$($extra[$k])".Trim() }
    $pairs = @()
    if ($u.Query.Length -gt 1) {
        foreach ($kv in $u.Query.Substring(1).Split('&')) {
            $p = $kv.Split('=', 2); $k = [Uri]::UnescapeDataString($p[0]); $v = if ($p.Count -gt 1) { [Uri]::UnescapeDataString($p[1]) } else { '' }
            $pairs += , @((ConvertTo-UriEncoded $k $false), (ConvertTo-UriEncoded $v $false))
        }
    }
    $cq = ($pairs | Sort-Object { $_[0] }, { $_[1] } | ForEach-Object { "$($_[0])=$($_[1])" }) -join '&'
    $names = @($hdr.Keys | Sort-Object)
    $canonHeaders = ($names | ForEach-Object { "${_}:$($hdr[$_])`n" }) -join ''
    $signed = $names -join ';'
    $path = if ($u.AbsolutePath) { $u.AbsolutePath } else { '/' }
    $canon = "$method`n$path`n$cq`n$canonHeaders`n$signed`n$payloadHash"
    $scope = "$date/$region/s3/aws4_request"
    $sts = "AWS4-HMAC-SHA256`n$amzDate`n$scope`n$(Get-StrSha256 $canon)"
    $k = Get-HmacStr (Get-HmacStr (Get-HmacStr (Get-HmacStr $Utf8.GetBytes("AWS4$sk") $date) $region) 's3') 'aws4_request'
    $sig = ConvertTo-HexLower (Get-HmacStr $k $sts)
    $hdr['Authorization'] = "AWS4-HMAC-SHA256 Credential=$ak/$scope, SignedHeaders=$signed, Signature=$sig"
    return $hdr
}
function Get-S3Url($d, [string]$key, [string]$query = '') {
    $ep = [Uri]($d.endpoint.TrimEnd('/'))
    $k = ConvertTo-UriEncoded $key $true
    $base = if ($ep.Host.EndsWith('amazonaws.com')) { "$($ep.Scheme)://$($d.bucket).$($ep.Authority)/$k" } else { "$($ep.Scheme)://$($ep.Authority)/$($d.bucket)/$k" }
    if ($query) { "${base}?$query" } else { $base }
}
function Invoke-S3($d, [string]$method, [string]$url, [string]$inFile = '', [string]$outFile = '') {
    $ph = if ($inFile) { Get-Sha256Hex $inFile } else { $EmptyHash }
    $region = if ($d.region) { $d.region } else { 'us-east-1' }
    $h = Get-SigV4Headers $method $url $region $d.access_key $d.secret_key $ph
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = $method; $req.Timeout = 300000; $req.ReadWriteTimeout = 300000
    foreach ($k in $h.Keys) { if ($k -ne 'host') { $req.Headers[$k] = $h[$k] } }
    if ($inFile) {
        $req.ContentLength = (Get-Item -LiteralPath $inFile).Length; $req.AllowWriteStreamBuffering = $false
        $rs = $req.GetRequestStream(); $fs = [IO.File]::OpenRead($inFile); $fs.CopyTo($rs, 1MB); $fs.Dispose(); $rs.Dispose()
    } elseif ($method -in 'PUT', 'POST') { $req.ContentLength = 0 }
    try { $resp = $req.GetResponse() } catch [Net.WebException] {
        $body = ''; if ($_.Exception.Response) { $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $body = $sr.ReadToEnd() }
        throw "S3 $method $($url.Split('?')[0]) -> $($_.Exception.Message) $($body -replace '\s+', ' ')"
    }
    try {
        $st = $resp.GetResponseStream()
        if ($outFile) { $o = [IO.File]::Create($outFile); $st.CopyTo($o, 1MB); $o.Dispose(); return $null }
        return (New-Object IO.StreamReader($st)).ReadToEnd()
    } finally { $resp.Dispose() }
}

# ---------------------------------------------------------------------------
# Destinations
# ---------------------------------------------------------------------------
function Get-Dest($d, [string]$slug) {
    if ($d.type -eq 'local') {
        return [pscustomobject]@{ d = $d; label = $d.path; dir = (Join-Path (Join-Path $d.path $HostName) $slug) }
    }
    $pre = (@($d.prefix.Trim('/'), $HostName, $slug) | Where-Object { $_ }) -join '/'
    return [pscustomobject]@{ d = $d; label = "s3://$($d.bucket)/$($d.prefix)"; prefix = "$pre/" }
}
function Send-ToDest($dest, [string]$path, [string]$name) {
    if ($dest.d.type -eq 'local') {
        New-Item -ItemType Directory -Path $dest.dir -Force | Out-Null
        $tmp = Join-Path $dest.dir "$name.part"; Copy-Item -LiteralPath $path $tmp -Force; Move-Item -LiteralPath $tmp (Join-Path $dest.dir $name) -Force
    } else {
        if ((Get-Item -LiteralPath $path).Length -gt 5GB) { throw 'archive is larger than 5 GB (single-upload limit); split the job into smaller jobs' }
        [void](Invoke-S3 $dest.d 'PUT' (Get-S3Url $dest.d ($dest.prefix + $name)) $path)
    }
}
function Get-FromDest($dest, [string]$name, [string]$out) {
    if ($dest.d.type -eq 'local') { Copy-Item -LiteralPath (Join-Path $dest.dir $name) $out -Force }
    else { [void](Invoke-S3 $dest.d 'GET' (Get-S3Url $dest.d ($dest.prefix + $name)) '' $out) }
}
function Get-DestArchives($dest) {
    if ($dest.d.type -eq 'local') {
        if (-not (Test-Path -LiteralPath $dest.dir)) { return @() }
        return @(Get-ChildItem -LiteralPath $dest.dir -Filter '*.ngbk' -File | ForEach-Object Name | Sort-Object -Descending)
    }
    $names = @(); $token = ''
    do {
        $q = 'list-type=2&prefix=' + (ConvertTo-UriEncoded $dest.prefix $false)
        if ($token) { $q += '&continuation-token=' + (ConvertTo-UriEncoded $token $false) }
        [xml]$x = Invoke-S3 $dest.d 'GET' (Get-S3Url $dest.d '' $q)
        foreach ($c in @($x.ListBucketResult.Contents)) { if ($c -and $c.Key) { $names += $c.Key.Substring($dest.prefix.Length) } }
        $token = if ($x.ListBucketResult.IsTruncated -eq 'true') { $x.ListBucketResult.NextContinuationToken } else { '' }
    } while ($token)
    return @($names | Where-Object { $_ -like '*.ngbk' } | Sort-Object -Descending)
}
function Remove-FromDest($dest, [string]$name) {
    foreach ($n in @($name, ($name -replace '\.ngbk$', '.json'))) {
        try {
            if ($dest.d.type -eq 'local') { Remove-Item -LiteralPath (Join-Path $dest.dir $n) -Force -ErrorAction Stop }
            else { [void](Invoke-S3 $dest.d 'DELETE' (Get-S3Url $dest.d ($dest.prefix + $n))) }
        } catch { Write-RunLog "could not delete ${n}: $($_.Exception.Message)" }
    }
}
function Get-ArchiveTime([string]$name) {
    if ($name -match '_(\d{8}-\d{6})\.ngbk$') { return [DateTime]::ParseExact($matches[1], 'yyyyMMdd-HHmmss', $null) }
    return [DateTime]::MinValue
}
function Invoke-Retention($dest, [int]$keepLast, [int]$keepDays) {
    $removed = @(); $i = 0
    foreach ($n in (Get-DestArchives $dest)) {
        $young = $keepDays -gt 0 -and ((Get-Date) - (Get-ArchiveTime $n)).TotalDays -lt $keepDays
        if ($i -ge [Math]::Max(1, $keepLast) -and -not $young) { Remove-FromDest $dest $n; $removed += $n }
        $i++
    }
    return $removed
}

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
function Find-Tool([string]$exe, [string[]]$globs) {
    $c = Get-Command $exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($g in $globs) { $f = Get-ChildItem $g -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1; if ($f) { return $f.FullName } }
    return $null
}
function Invoke-Dump([string]$exe, [string[]]$dumpArgs, [string]$outFile, [hashtable]$envVars) {
    $psi = New-Object Diagnostics.ProcessStartInfo($exe)
    $psi.Arguments = ($dumpArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    foreach ($k in $envVars.Keys) { $psi.EnvironmentVariables[$k] = $envVars[$k] }
    $p = [Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $o = [IO.File]::Create($outFile); $p.StandardOutput.BaseStream.CopyTo($o); $o.Dispose()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "$(Split-Path $exe -Leaf) failed: $($errTask.Result)" }
    if ((Get-Item $outFile).Length -eq 0) { throw "$(Split-Path $exe -Leaf) produced an empty dump" }
}
function Save-Database($db, [string]$outDir) {
    $name = ($db.name -replace '[^A-Za-z0-9_.-]+', '-')
    $dbs = @("$($db.database)".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    switch ($db.engine) {
        'mysql' {
            $exe = Find-Tool 'mysqldump.exe' @("$env:ProgramFiles\MySQL\*\bin\mysqldump.exe", "$env:ProgramFiles\MariaDB*\bin\mysqldump.exe", 'C:\xampp\mysql\bin\mysqldump.exe')
            if (-not $exe) { throw 'mysqldump.exe not found' }
            $a = @('--single-transaction', '--quick', '--routines', '--events', '--triggers', '-h', $(if ($db.host) { $db.host } else { 'localhost' }),
                '-P', $(if ($db.port) { "$($db.port)" } else { '3306' }), '-u', $(if ($db.username) { $db.username } else { 'root' }))
            $a += $(if ($dbs) { @('--databases') + $dbs } else { @('--all-databases') })
            Invoke-Dump $exe $a (Join-Path $outDir "$name.mysql.sql") @{ MYSQL_PWD = "$($db.password)" }
        }
        'postgres' {
            $conn = @('-h', $(if ($db.host) { $db.host } else { 'localhost' }), '-p', $(if ($db.port) { "$($db.port)" } else { '5432' }), '-U', $(if ($db.username) { $db.username } else { 'postgres' }))
            if ($dbs) {
                $exe = Find-Tool 'pg_dump.exe' @("$env:ProgramFiles\PostgreSQL\*\bin\pg_dump.exe"); if (-not $exe) { throw 'pg_dump.exe not found' }
                foreach ($d in $dbs) { Invoke-Dump $exe ($conn + @('--clean', '--if-exists', $d)) (Join-Path $outDir "$name.$d.postgres.sql") @{ PGPASSWORD = "$($db.password)" } }
            } else {
                $exe = Find-Tool 'pg_dumpall.exe' @("$env:ProgramFiles\PostgreSQL\*\bin\pg_dumpall.exe"); if (-not $exe) { throw 'pg_dumpall.exe not found' }
                Invoke-Dump $exe ($conn + @('--clean', '--if-exists')) (Join-Path $outDir "$name.postgres.sql") @{ PGPASSWORD = "$($db.password)" }
            }
        }
        'mssql' {
            $exe = Find-Tool 'sqlcmd.exe' @("$env:ProgramFiles\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE", "$env:ProgramFiles\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE")
            if (-not $exe) { throw 'sqlcmd.exe not found' }
            $server = if ($db.host) { $db.host } else { 'localhost' }
            $auth = if ($db.username) { @('-U', $db.username, '-P', "$($db.password)") } else { @('-E') }
            if (-not $dbs) {
                $list = & $exe -S $server @auth -h -1 -W -Q "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0" 2>&1
                $dbs = @($list | Where-Object { $_ -and $_ -notmatch '^\s*$' } | ForEach-Object { "$_".Trim() })
            }
            # SQL Server writes the .bak itself, so give its service account write access to a dedicated folder
            $sqlDir = Join-Path $StateDir 'sqlstage'; New-Item -ItemType Directory -Path $sqlDir -Force | Out-Null
            foreach ($svc in Get-CimInstance Win32_Service -Filter "Name LIKE 'MSSQL%'" -ErrorAction SilentlyContinue) {
                & icacls $sqlDir /grant "NT SERVICE\$($svc.Name):(OI)(CI)M" 2>&1 | Out-Null
            }
            foreach ($d in $dbs) {
                $bak = Join-Path $sqlDir "$name.$d.bak"
                $out = & $exe -S $server @auth -b -Q "BACKUP DATABASE [$($d -replace '\]', ']]')] TO DISK = N'$bak' WITH COPY_ONLY, INIT, CHECKSUM" 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path $bak)) { throw "SQL Server backup of $d failed: $($out -join ' ')" }
                Move-Item $bak (Join-Path $outDir "$name.$d.mssql.bak") -Force
            }
        }
        'sqlite' {
            $path = if ($db.host) { $db.host } else { $db.database }
            if (-not $path -or -not (Test-Path -LiteralPath $path)) { throw "SQLite file not found: $path (put the file path in the Host field)" }
            Copy-Item -LiteralPath $path (Join-Path $outDir "$name.sqlite") -Force
            Write-RunLog 'note: SQLite on Windows is copied as a file; stop writes during the backup window for a consistent copy'
        }
        default { throw "unsupported database engine '$($db.engine)'" }
    }
}
function Save-ConfigSnapshot([string]$dir) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $snap = {
        param($file, $sb)
        try { & $sb 2>&1 | Out-String -Width 400 | Set-Content -LiteralPath (Join-Path $dir $file) -Encoding UTF8 } catch { "error: $_" | Set-Content (Join-Path $dir $file) }
    }
    & netsh advfirewall export (Join-Path $dir 'firewall.wfw') 2>&1 | Out-Null
    & schtasks /query /xml ONE 2>$null | Set-Content -LiteralPath (Join-Path $dir 'scheduled-tasks.xml') -Encoding UTF8
    & $snap 'services.txt' { Get-CimInstance Win32_Service | Sort-Object Name | Format-Table Name, State, StartMode, StartName, PathName -AutoSize }
    & $snap 'installed-programs.txt' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher -AutoSize }
    & $snap 'network.txt' { ipconfig /all; route print }
    & $snap 'local-users.txt' { Get-LocalUser | Format-Table Name, Enabled, LastLogon -AutoSize; Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue }
    & $snap 'shares.txt' { Get-SmbShare -ErrorAction SilentlyContinue | Format-Table Name, Path, Description -AutoSize }
    & $snap 'windows-features.txt' { if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { Get-WindowsFeature | Where-Object Installed } else { Get-WindowsOptionalFeature -Online | Where-Object State -eq Enabled | Select-Object FeatureName } }
    & $snap 'disks.txt' { Get-Volume | Format-Table -AutoSize }
    Copy-Item "$env:windir\System32\drivers\etc\hosts" (Join-Path $dir 'hosts') -ErrorAction SilentlyContinue
}

function New-BackupArchive($job, [string]$work, [string]$zipPath) {
    $src = $job.sources
    $excludes = @($src.excludes | Where-Object { $_ })
    $items = New-Object System.Collections.ArrayList   # @(path, archive-prefix, label)
    if ($src.website) {
        $found = @("$env:SystemDrive\inetpub", "$env:windir\System32\inetsrv\config", 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\nginx\conf', 'C:\nginx\html') | Where-Object { Test-Path $_ }
        if (-not $found) { Write-RunLog 'website preset: no IIS/XAMPP/WAMP/nginx folders found' }
        foreach ($p in $found) { [void]$items.Add(@($p, ('website/' + ($p -replace ':', '')), 'website')) }
        $iis = Join-Path $work 'generated-iis'; New-Item -ItemType Directory $iis -Force | Out-Null
        $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
        if (Test-Path $appcmd) { & $appcmd list site /config /xml 2>&1 | Set-Content (Join-Path $iis 'iis-sites.xml') -Encoding UTF8 }
        & netsh http show sslcert 2>&1 | Set-Content (Join-Path $iis 'ssl-bindings.txt') -Encoding UTF8
        [void]$items.Add(@($iis, 'website/generated', 'website'))
    }
    if ($src.config) {
        $cfg = Join-Path $work 'generated-config'; Save-ConfigSnapshot $cfg
        [void]$items.Add(@($cfg, 'config', 'config'))
    }
    foreach ($p in @($src.folders | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $p)) { throw "folder not found: $p" }
        [void]$items.Add(@($p, ('folders/' + ($p -replace ':', '')), 'folder'))
    }
    $dbDir = Join-Path $work 'databases'; New-Item -ItemType Directory $dbDir -Force | Out-Null
    foreach ($db in @($src.databases | Where-Object { $_ })) { Write-RunLog "dumping database $($db.name) ($($db.engine))"; Save-Database $db $dbDir }
    if (Get-ChildItem $dbDir) { [void]$items.Add(@($dbDir, 'databases', 'database')) }

    $stats = @{}; $skipped = New-Object System.Collections.ArrayList
    $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
    try {
        foreach ($it in $items) {
            $root = (Get-Item -LiteralPath $it[0]).FullName.TrimEnd('\')
            $files = if (Test-Path -LiteralPath $root -PathType Leaf) { @(Get-Item -LiteralPath $root) } else { @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue -Attributes !ReparsePoint) }
            foreach ($f in $files) {
                $full = $f.FullName
                if ($excludes | Where-Object { $full -like $_ -or $f.Name -like $_ }) { continue }
                $rel = if ($full.Length -gt $root.Length) { $full.Substring($root.Length).TrimStart('\') } else { $f.Name }
                $entry = ($it[1].TrimEnd('/') + '/' + $rel) -replace '\\', '/'
                try {
                    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $full, $entry, [IO.Compression.CompressionLevel]::Optimal)
                    if (-not $stats[$it[2]]) { $stats[$it[2]] = @(0, [long]0) }
                    $stats[$it[2]][0]++; $stats[$it[2]][1] += $f.Length
                } catch { [void]$skipped.Add("${full}: $($_.Exception.InnerException.Message)$($_.Exception.Message)") }
            }
        }
    } finally { $zip.Dispose() }
    if ($skipped.Count) { Write-RunLog "skipped $($skipped.Count) file(s) that could not be read (in use / access denied)" }
    $contents = @($stats.Keys | ForEach-Object { @{ type = $_; files = $stats[$_][0]; bytes = $stats[$_][1] } })
    return @{ contents = $contents; skipped = @($skipped | Select-Object -First 50) }
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
function Invoke-Backup($job, [string]$work) {
    $t0 = Get-Date
    $name = '{0}_{1}_{2}.ngbk' -f ($HostName -replace '[^A-Za-z0-9.-]', '-'), $job.slug, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $zipPath = Join-Path $work 'archive.zip'
    $built = New-BackupArchive $job $work $zipPath
    $enc = Join-Path $work $name
    Protect-File $zipPath $enc ([Convert]::FromBase64String($job.key))
    Remove-Item $zipPath -Force
    $digest = Get-Sha256Hex $enc; $size = (Get-Item $enc).Length
    $manifest = [ordered]@{ format = 'netguard-backup/1'; host = $HostName; job_id = $job.id; job = $job.name; archive = $name
        created = [DateTime]::UtcNow.ToString('o'); sha256 = $digest; size = $size; encrypted = $true; archive_type = 'zip'
        contents = $built.contents; skipped = $built.skipped; tool = "netguard-windows/$ToolVersion" }
    $man = Join-Path $work ($name -replace '\.ngbk$', '.json')
    [IO.File]::WriteAllText($man, (ConvertTo-Json -InputObject $manifest -Depth 5), $Utf8)
    $destStatus = @(); $okAny = $false
    foreach ($d in @($job.destinations)) {
        $dest = Get-Dest $d $job.slug
        try {
            Send-ToDest $dest $enc $name
            Send-ToDest $dest $man ($name -replace '\.ngbk$', '.json')
            $removed = @(Invoke-Retention $dest ([int]$job.retention.keep_last) ([int]$job.retention.keep_days))
            $destStatus += @{ dest = $dest.label; ok = $true; removed_old = $removed }; $okAny = $true
            Write-RunLog "stored on $($dest.label) (removed $($removed.Count) old)"
        } catch {
            $destStatus += @{ dest = $dest.label; ok = $false; error = "$($_.Exception.Message)" }
            Write-RunLog "FAILED to store on $($dest.label): $($_.Exception.Message)"
        }
    }
    $allOk = -not ($destStatus | Where-Object { -not $_.ok })
    return @{ status = $(if ($allOk) { 'ok' } else { 'failed' }); archive = $name; sha256 = $digest; size = $size
        files = (@($built.contents | ForEach-Object { [long]$_.files }) | Measure-Object -Sum).Sum
        details = @{ destinations = $destStatus; contents = $built.contents; skipped = $built.skipped
            duration_s = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1); partial = ($okAny -and -not $allOk) } }
}

function Invoke-TestOrRestore($job, [string]$work, [string]$mode) {
    $t0 = Get-Date
    $checks = New-Object System.Collections.ArrayList
    function Add-Check($n, $ok, $detail = '') { [void]$checks.Add(@{ check = $n; ok = [bool]$ok; detail = "$detail" }); Write-RunLog ("{0} {1} {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $n, $detail) }
    $errors = @(); $got = $null
    foreach ($d in @($job.destinations)) {
        $dest = Get-Dest $d $job.slug
        try {
            $names = @(Get-DestArchives $dest)
            $name = if ($Archive) { $Archive } elseif ($names) { $names[0] } else { $null }
            if (-not $name -or $names -notcontains $name) { $errors += "$($dest.label): $(if (-not $names) { 'no archives' } else { "$name not found" })"; continue }
            $enc = Join-Path $work $name; Get-FromDest $dest $name $enc
            $man = $null; try { Get-FromDest $dest ($name -replace '\.ngbk$', '.json') (Join-Path $work 'm.json'); $man = Get-Content (Join-Path $work 'm.json') -Raw | ConvertFrom-Json } catch { }
            $got = @{ dest = $dest; name = $name; enc = $enc; man = $man }; break
        } catch { $errors += "$($dest.label): $($_.Exception.Message)" }
    }
    if (-not $got) { throw "could not fetch a backup: $($errors -join '; ')" }
    Add-Check "downloaded from $($got.dest.label)" $true $got.name
    $digest = Get-Sha256Hex $got.enc
    Add-Check 'checksum matches manifest' ((-not $got.man) -or $got.man.sha256 -eq $digest) $digest.Substring(0, 16)
    $zipPath = Join-Path $work 'a.zip'
    try { Unprotect-File $got.enc $zipPath ([Convert]::FromBase64String($job.key)); Add-Check 'decrypts with the job key (integrity verified)' $true }
    catch { Add-Check 'decrypts with the job key (integrity verified)' $false $_.Exception.Message; throw }
    Remove-Item $got.enc -Force
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    $restoredTo = $null
    try {
        $entries = @($zip.Entries | Where-Object { $_.Name })
        Add-Check 'archive readable' $true "$($entries.Count) files"
        if ($got.man -and $got.man.contents) {
            $expected = (@($got.man.contents | ForEach-Object { [long]$_.files }) | Measure-Object -Sum).Sum
            Add-Check 'file count matches manifest' ($entries.Count -ge [Math]::Floor($expected * 0.99)) "$($entries.Count) of $expected"
        }
        foreach ($e in $entries | Where-Object { $_.FullName -like 'databases/*' }) {
            $s = $e.Open(); $buf = New-Object byte[] 200; $n = $s.Read($buf, 0, 200); $s.Dispose()
            $head = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $good = $e.Length -gt 0 -and ($head -match 'MySQL dump|MariaDB dump|PostgreSQL|^SQLite format 3|TAPE|^--' -or $e.FullName -like '*.bak')
            Add-Check "database dump looks valid: $($e.Name)" $good "$($e.Length) bytes"
        }
        $dest = if ($mode -eq 'restore') {
            if ($Target) { $Target } else { Join-Path $StateDir ("restores\{0}-{1}" -f $job.slug, (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        } else { Join-Path $work 'sample' }
        if ((Test-Path $dest) -and (Get-ChildItem $dest -Force | Select-Object -First 1)) { throw "restore target $dest is not empty; choose a new folder" }
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $base = [IO.Path]::GetFullPath($dest).TrimEnd('\') + '\'
        $list = if ($mode -eq 'restore') { $entries } else { $entries | Select-Object -First 200 }
        foreach ($e in $list) {
            $out = [IO.Path]::GetFullPath((Join-Path $dest $e.FullName))
            if (-not $out.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { continue }      # zip-slip guard
            New-Item -ItemType Directory -Path (Split-Path $out) -Force | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $out, $false)
        }
        if ($mode -eq 'restore') { $restoredTo = $dest; Add-Check 'extracted' $true $dest } else { Add-Check 'sample of files extracts' $true }
    } finally { $zip.Dispose() }
    $ok = -not ($checks | Where-Object { -not $_.ok })
    return @{ status = $(if ($ok) { 'ok' } else { 'failed' }); archive = $got.name; sha256 = $digest; files = $entries.Count
        details = @{ checks = @($checks); archive_age_h = [Math]::Round(((Get-Date) - (Get-ArchiveTime $got.name)).TotalHours, 1)
            restored_to = $restoredTo; duration_s = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1) } }
}

# ---------------------------------------------------------------------------
if ($LibOnly) { return }
if (-not $JobFile -or -not $ResultFile) { throw '-JobFile and -ResultFile are required' }
$res = @{ run_ref = $RunRef; kind = $Mode; started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
$staging = Join-Path $StateDir 'staging'; New-Item -ItemType Directory -Path $staging -Force | Out-Null
$work = Join-Path $staging ("ng-" + $RunRef.Substring(0, 8)); New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
    $res.job_id = $job.id
    $r = if ($Mode -eq 'backup') { Invoke-Backup $job $work } else { Invoke-TestOrRestore $job $work $Mode }
    foreach ($k in $r.Keys) { $res[$k] = $r[$k] }
} catch {
    Write-RunLog "ERROR: $($_.Exception.Message)"
    $res.status = 'failed'; $res.details = @{ error = "$($_.Exception.Message)" }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
$res.finished = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$res.log = ($script:Log -join "`n")
[IO.File]::WriteAllText("$ResultFile.tmp", (ConvertTo-Json -InputObject $res -Depth 8), $Utf8)
Move-Item -LiteralPath "$ResultFile.tmp" -Destination $ResultFile -Force
