# Build-Offline-Wheels.ps1 — make a NodeWatch package that installs with NO internet access.
#
# Run on any Windows PC that can reach PyPI (or through your proxy), from the repository root:
#   powershell -ExecutionPolicy Bypass -File release\Build-Offline-Wheels.ps1
# It downloads every wheel NodeWatch needs (core + optional SNMP components) for 64-bit Windows /
# Python 3.12 into runtime\wheels. Then run release\generate_integrity.py and package as usual:
# the launcher installs from runtime\wheels first and only falls back to PyPI if a wheel is missing.
# Proxy: pip uses the Windows proxy settings and HTTPS_PROXY; for an authenticated proxy pass
#   -Proxy http://user@proxy.example.com:8080   (pip will prompt for the password)
param([string]$Proxy = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "runtime\wheels"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Get-ChildItem $dest -Filter *.whl | Remove-Item -Force
$py = Join-Path $root "runtime\python\python.exe"
if (-not (Test-Path $py)) { $py = "py" }
$common = @("-m", "pip", "download", "--only-binary=:all:", "--platform", "win_amd64", "--python-version", "3.12",
            "--implementation", "cp", "--dest", $dest)
if ($Proxy) { $common += @("--proxy", $Proxy) }
# The hash-pinned lock (when present) is downloaded on its own: pip refuses to mix hashed and unhashed files.
$core = Join-Path $root "requirements.lock"
if (-not (Test-Path $core)) { $core = Join-Path $root "requirements.txt" }
foreach ($req in @($core, (Join-Path $root "requirements-optional.txt"))) {
    $pipArgs = $common + @("-r", $req)
    & $py @pipArgs
    if ($LASTEXITCODE -ne 0) { throw "pip download failed for $req ($LASTEXITCODE)" }
}
$n = (Get-ChildItem $dest -Filter *.whl).Count
if ($n -eq 0) { throw "No wheels were downloaded into $dest" }
Write-Host "Downloaded $n wheels into $dest. Now run: python release\generate_integrity.py --update-launcher"
