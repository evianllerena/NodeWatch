<#
Record what the shipped v0.10.42 Windows launcher does on a clean Windows machine (GitHub runner).
It starts NodeWatch\NodeWatch.exe from an extracted copy, watches for up to $Seconds, and reports:
processes it starts, window titles (a message box shows as a title), which port answers the probe,
and the NodeWatch log files under %LOCALAPPDATA%\NodeWatch. Everything is then stopped.
Results are printed as GitHub annotations, because run logs are not readable from outside.
#>
param([Parameter(Mandatory)] [string] $Root, [int] $Seconds = 120)

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

Note "parity timeline" ($timeline -join "`n")
Note "parity backend" ($(if ($answered) { $answered } else { "no port 8765-8795 answered the probe within $Seconds s" }))

if (Test-Path $data) {
    $tree = Get-ChildItem $data -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch "\\pycache\\|\\runtime" } |
        ForEach-Object { $_.FullName.Substring($data.Length) + $(if ($_.PSIsContainer) { "\" } else { " ($($_.Length) B)" }) }
    Note "parity data folder" (($tree | Select-Object -First 60) -join "`n")
    foreach ($log in (Get-ChildItem $data -Recurse -Include *.log -ErrorAction SilentlyContinue)) {
        $lines = Get-Content $log.FullName -Tail 40 -ErrorAction SilentlyContinue
        Note ("log " + $log.FullName.Substring($data.Length)) ($lines -join "`n")
    }
} else {
    Note "parity data folder" "not created"
}

# Stop everything this run started.
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like "$Root*" -or $_.ExecutablePath -like "$data*") } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
exit 0
