param(
  [string]$PythonVersion = '3.12.10',
  # SHA-256 of python-<version>-embed-amd64.zip as published on python.org
  # (https://www.python.org/downloads/release/python-31210/ -> "SHA256" column).
  [Parameter(Mandatory = $true)][string]$ExpectedZipSha256
)
# LEGACY (pre-v0.10.12) alternative. Releases now stage the python-build-standalone
# interpreter with tools\stage_runtime.py into runtime\python\ and build
# release\backend_host as runtime\NodeWatchBackend.exe (docs\RELEASE_PROCESS.md).
# This script deletes runtime\ entirely, so it refuses to run over that layout.
$ErrorActionPreference = 'Stop'
if (Test-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'runtime\python')) {
  throw 'runtime\python exists (v0.10.12 bundled interpreter layout). Use tools\stage_runtime.py instead of this legacy script.'
}
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$internal = Join-Path $root '_internal'
if (-not (Test-Path $internal)) { $internal = Split-Path -Parent $PSScriptRoot }
$runtime = Join-Path $internal 'runtime'
$zip = Join-Path $env:TEMP "python-$PythonVersion-embed-amd64.zip"
$url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
Remove-Item $runtime -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $runtime | Out-Null
Write-Host "Downloading official CPython embeddable runtime $PythonVersion..."
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$actualZipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actualZipHash -ne $ExpectedZipSha256.ToLower()) {
  throw "Downloaded runtime hash $actualZipHash does not match the expected $ExpectedZipSha256. Refusing to bundle it."
}
Expand-Archive -Path $zip -DestinationPath $runtime -Force
$python = Join-Path $runtime 'python.exe'
if (-not (Test-Path $python)) { throw 'Embeddable python.exe was not found after extraction.' }
$site = Join-Path $runtime 'site-packages'
New-Item -ItemType Directory -Path $site -Force | Out-Null
Write-Host 'Installing pinned NodeWatch dependencies into bundled site-packages...'
$lock = Join-Path $internal 'requirements.lock'
if (-not (Test-Path $lock)) { throw 'requirements.lock is missing. Run release\Update-Lockfile.ps1 first.' }
py -3.12 -m pip install --disable-pip-version-check --no-input --only-binary=:all: --require-hashes --no-compile --target $site -r $lock
if ($LASTEXITCODE -ne 0) { throw 'Hash-verified dependency installation failed.' }
$pth = Join-Path $runtime 'python312._pth'
@('python312.zip','.','site-packages','..','import site') | Set-Content -Path $pth -Encoding ascii
Rename-Item -Path $python -NewName 'NodeWatchBackend.exe'
$backend = Join-Path $runtime 'NodeWatchBackend.exe'
$env:PYTHONPYCACHEPREFIX = Join-Path $env:TEMP 'nodewatch-runtime-check-pycache'
& $backend -c "import fastapi,starlette,uvicorn,jinja2; print('NodeWatch bundled runtime verified')"
if ($LASTEXITCODE -ne 0) { throw 'Bundled runtime verification failed.' }
# The launcher rejects any file in runtime\ that the manifest does not list; never ship caches.
Get-ChildItem $runtime -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
Write-Host "Bundled runtime ready: $backend"
Write-Host 'Next: run release\generate_integrity.py so the manifest covers runtime\NodeWatchBackend.exe, then rebuild the launcher.' 
