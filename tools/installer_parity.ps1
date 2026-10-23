# Black-box record of a Windows installer's behaviour (run on a clean GitHub Windows runner).
# Writes text files into -Out: what changed on disk and in HKCU, exit codes, processes it started, and the
# windows (titles, buttons, texts) it shows when run interactively.
param([Parameter(Mandatory)] [string] $Installer, [Parameter(Mandatory)] [string] $Out)
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Installer = (Resolve-Path $Installer).Path

$places = @(
  "$env:LOCALAPPDATA\Programs", "$env:LOCALAPPDATA\NodeWatch", "$env:APPDATA\NodeWatch",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:TEMP"
)
$regRoots = @("HKCU:\Software")

function Snap-Files {
  $rows = @()
  foreach ($p in $places) {
    if (Test-Path $p) {
      $rows += Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\Temp\\(gh|_runner|msedge|chocolatey)' } |
        ForEach-Object { "{0}|{1}" -f $_.FullName, ($(if ($_.PSIsContainer) { "dir" } else { $_.Length })) }
    }
  }
  return $rows
}
function Snap-Reg {
  $rows = @()
  foreach ($r in $regRoots) {
    Get-ChildItem $r -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      $key = $_
      $rows += "KEY $($key.Name)"
      foreach ($v in $key.GetValueNames()) { $rows += "VAL $($key.Name) :: $v = $($key.GetValue($v))" }
    }
  }
  return $rows
}
function Diff($before, $after, $name) {
  $added = $after | Where-Object { $before -notcontains $_ }
  $removed = $before | Where-Object { $after -notcontains $_ }
  @("ADDED ($($added.Count))") + $added + @("", "REMOVED ($($removed.Count))") + $removed | Set-Content (Join-Path $Out $name)
}
function Procs { Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId)|$($_.Name)|$($_.ExecutablePath)|$($_.CommandLine)" } }

function Record-UI($name) {
  Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
  $p = Start-Process -FilePath $Installer -PassThru
  $seen = @()
  for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 1
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
    $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
    foreach ($w in $wins) {
      $seen += "WINDOW '$($w.Current.Name)' class=$($w.Current.ClassName)"
      foreach ($c in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)) {
        $seen += "  $($c.Current.ControlType.ProgrammaticName) '$($c.Current.Name)'"
      }
    }
  }
  if ($p.HasExited) { $seen += "process exited with $($p.ExitCode)" } else { $seen += "still running after 12 s (killed, nothing clicked)"; $p | Stop-Process -Force }
  ($seen | Select-Object -Unique) | Set-Content (Join-Path $Out $name)
  Get-Process | Where-Object { $_.Name -match "NodeWatch|python|nwhost" } | Stop-Process -Force -ErrorAction SilentlyContinue
}

# 0. Interactive run on a clean machine: windows and texts shown, nothing clicked
$f00 = Snap-Files
Record-UI "0-interactive-clean-ui.txt"
Diff $f00 (Snap-Files) "0-interactive-clean-files.txt"

# 1. Silent install (/S)
$f0 = Snap-Files; $r0 = Snap-Reg; $p0 = Procs
$p = Start-Process -FilePath $Installer -ArgumentList "/S" -PassThru -Wait
"silent install exit code: $($p.ExitCode)" | Set-Content (Join-Path $Out "1-silent-exit.txt")
Start-Sleep -Seconds 15
$f1 = Snap-Files; $r1 = Snap-Reg; $p1 = Procs
Diff $f0 $f1 "1-silent-files.txt"
Diff $r0 $r1 "1-silent-registry.txt"
Diff $p0 $p1 "1-silent-processes.txt"
Get-CimInstance Win32_Process | Where-Object { $_.Name -match "NodeWatch|python|msedge|nwhost" } | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.Name -match "NodeWatch|python|nwhost" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Shortcut targets, if any were made
$lnk = @()
$shell = New-Object -ComObject WScript.Shell
foreach ($line in $f1 | Where-Object { $f0 -notcontains $_ -and $_ -match '\.lnk\|' }) {
  $path = $line.Split('|')[0]
  $s = $shell.CreateShortcut($path)
  $lnk += "$path -> $($s.TargetPath) $($s.Arguments) (in $($s.WorkingDirectory); icon $($s.IconLocation))"
}
($lnk.Count ? $lnk : @("no shortcuts created")) | Set-Content (Join-Path $Out "1-silent-shortcuts.txt")

# 2. Run again with /S over the existing install
$p = Start-Process -FilePath $Installer -ArgumentList "/S" -PassThru -Wait
"second silent install exit code: $($p.ExitCode)" | Set-Content (Join-Path $Out "2-reinstall-exit.txt")
Start-Sleep -Seconds 10
Get-Process | Where-Object { $_.Name -match "NodeWatch|python|nwhost" } | Stop-Process -Force -ErrorAction SilentlyContinue

# 3. Other switches
foreach ($arg in @("/?", "/help", "--help")) {
  $p = Start-Process -FilePath $Installer -ArgumentList $arg -PassThru
  if (-not $p.WaitForExit(8000)) { $p | Stop-Process -Force; "$arg : still running after 8 s (killed)" } else { "$arg : exit $($p.ExitCode)" }
} | Set-Content (Join-Path $Out "3-switches.txt")
Get-Process | Where-Object { $_.Name -match "NodeWatch|python|nwhost" } | Stop-Process -Force -ErrorAction SilentlyContinue

# 4. Interactive run over an existing install
Record-UI "4-interactive-installed-ui.txt"
