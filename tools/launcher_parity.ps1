<#
Record what the shipped v0.10.42 Windows launcher does on a clean Windows machine (GitHub runner).
It starts NodeWatch\NodeWatch.exe from an extracted copy, watches for up to $Seconds, and reports:
processes it starts, window titles (a message box shows as a title), which port answers the probe,
and the NodeWatch log files under %LOCALAPPDATA%\NodeWatch. Everything is then stopped.
Results are printed as GitHub annotations, because run logs are not readable from outside.
#>
param([Parameter(Mandatory)] [string] $Root, [int] $Seconds = 120, [string] $ExpectBuild = "")

$ErrorActionPreference = "Continue"
function Note([string] $title, [string] $text) {
    $t = ($text -replace "%", "%25") -replace "`r", "" -replace "`n", "%0A"
    if ($t.Length -gt 3800) { $t = $t.Substring(0, 3800) + "%0A…(cut)" }
    Write-Output "::notice title=$title::$t"
}

$exe = Join-Path $Root "NodeWatch\NodeWatch.exe"
$data = Join-Path $env:LOCALAPPDATA "NodeWatch"
Note "parity setup" "launcher=$exe`nexists=$(Test-Path $exe)`nLOCALAPPDATA data folder exists before start=$(Test-Path $data)`nuser=$env:USERNAME"

$p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
$timeline = New-Object System.Collections.Generic.List[string]
$seen = @{}
$answered = $null
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like "$Root*" -or $_.ExecutablePath -like "$data*" -or $_.Name -match "NodeWatch|python|msedge") }
    foreach ($x in $procs) {
        $key = "$($x.ProcessId)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = 1
            $timeline.Add(("{0,5:N1}s start pid={1} parent={2} {3}" -f $sw.Elapsed.TotalSeconds, $x.ProcessId, $x.ParentProcessId, $x.ExecutablePath))
        }
    }
    foreach ($w in (Get-Process | Where-Object { $_.MainWindowTitle })) {
        $key = "w$($w.Id):$($w.MainWindowTitle)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = 1
            $timeline.Add(("{0,5:N1}s window pid={1} {2}: '{3}'" -f $sw.Elapsed.TotalSeconds, $w.Id, $w.ProcessName, $w.MainWindowTitle))
        }
    }
    if (-not $answered) {
        foreach ($port in 8765..8795) {
            try {
                $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 "http://127.0.0.1:$port/api/status?probe=true"
                $answered = "port $port after $([int]$sw.Elapsed.TotalSeconds)s: $($r.Content)"
                $timeline.Add("$([int]$sw.Elapsed.TotalSeconds)s probe answered on $port")
                break
            } catch { }
        }
    }
    if ($p.HasExited -and -not $seen.ContainsKey("exit")) {
        $seen["exit"] = 1
        $timeline.Add(("{0,5:N1}s launcher exited code={1}" -f $sw.Elapsed.TotalSeconds, $p.ExitCode))
    }
    if ($answered -and $sw.Elapsed.TotalSeconds -gt 45) { break }
    Start-Sleep -Milliseconds 1000
}

# Second launch while the first is running: v0.10.42 should reuse the running backend.
if ($answered) {
    $before = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$Root*" } | ForEach-Object { $_.ProcessId })
    $p2 = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
    $t0 = $sw.Elapsed.TotalSeconds
    while (-not $p2.HasExited -and ($sw.Elapsed.TotalSeconds - $t0) -lt 30) { Start-Sleep -Milliseconds 500 }
    Start-Sleep -Seconds 3
    $new = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$Root*" -and $before -notcontains $_.ProcessId -and $_.ProcessId -ne $p2.Id } |
        ForEach-Object { "pid=$($_.ProcessId) parent=$($_.ParentProcessId) $($_.ExecutablePath)" })
    $timeline.Add(("second launch: exited={0} code={1} after {2:N1}s; new processes: {3}" -f $p2.HasExited, $(if ($p2.HasExited) { $p2.ExitCode } else { "-" }), ($sw.Elapsed.TotalSeconds - $t0), $(if ($new) { $new -join "; " } else { "none" })))
}

Note "parity timeline" ($timeline -join "`n")
Note "parity backend" ($(if ($answered) { $answered } else { "no port 8765-8795 answered the probe within $Seconds s" }))

if (Test-Path $data) {
    $tree = Get-ChildItem $data -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch "\\pycache\\|\\runtime" } |
        ForEach-Object { $_.FullName.Substring($data.Length) + $(if ($_.PSIsContainer) { "\" } else { " ($($_.Length) B)" }) }
    Note "parity data folder" (($tree | Select-Object -First 60) -join "`n")
    $logs = @(Get-ChildItem (Join-Path $data "logs") -File -ErrorAction SilentlyContinue) + @(Get-ChildItem (Join-Path $data "app-window") -Filter *.log -File -ErrorAction SilentlyContinue)
    foreach ($log in $logs) {
        $lines = Get-Content $log.FullName -Tail 40 -ErrorAction SilentlyContinue
        Note ("log " + $log.FullName.Substring($data.Length)) ($lines -join "`n")
    }
} else {
    Note "parity data folder" "not created"
}

# Stop everything this run started.
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like "$Root*" -or $_.ExecutablePath -like "$data*") } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if ($ExpectBuild -and -not ($answered -and $answered.Contains("`"build`":`"$ExpectBuild`""))) {
    Write-Output "::error title=parity::the backend did not answer as build $ExpectBuild"
    exit 1
}
exit 0
