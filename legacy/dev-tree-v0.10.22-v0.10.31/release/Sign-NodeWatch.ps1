param(
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [string]$Executable = "$(Join-Path $PSScriptRoot '..\..\NodeWatch.exe')",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = 'Stop'
$thumb = ($CertificateThumbprint -replace '\s','').ToUpperInvariant()
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.Thumbprint -eq $thumb } |
    Select-Object -First 1
if (-not $cert) { throw "Code-signing certificate not found: $thumb" }
if (-not ($cert.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3')) {
    throw 'Selected certificate is not valid for code signing.'
}
if (-not (Test-Path -LiteralPath $Executable)) { throw "Executable not found: $Executable" }

$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK signing tools.' }

& $signtool sign /sha1 $thumb /fd SHA256 /tr $TimestampUrl /td SHA256 $Executable
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }
& $signtool verify /pa /v $Executable
if ($LASTEXITCODE -ne 0) { throw "signtool verify failed with exit code $LASTEXITCODE" }

Write-Host "Signature verified: $Executable"
Write-Host "Confirm the certificate Subject identifies the intended BWN publisher before distribution."
