# Builds a portable, self-contained TrustGuard.exe (no .NET install required on target PCs)
# and packs a ready-to-distribute folder + zip under ..\dist\.
#
# Requirements on the BUILD machine only: .NET 8 SDK (win-x64).
# Target machines: Windows 10 1607+ / Windows 11, x64. No installer, no runtime needed.

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$Dotnet = "dotnet"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $root "TrustGuard"
$dist = Join-Path (Split-Path -Parent $root) "dist"
$stage = Join-Path $dist "TrustGuard-$Version-win-x64"

Write-Host "==> publishing self-contained single-file exe"
& $Dotnet publish (Join-Path $proj "TrustGuard.csproj") -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    -o (Join-Path $proj "publish") --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "==> staging distribution folder"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage "scripts") | Out-Null

Copy-Item (Join-Path $proj "publish\TrustGuard.exe") $stage
Copy-Item (Join-Path $root "..\public\downloads\Check-EmSignTrust.ps1") (Join-Path $stage "scripts")
Copy-Item (Join-Path $root "..\public\downloads\fingerprints.json") (Join-Path $stage "scripts")
Copy-Item (Join-Path $root "README-Windows.txt") $stage

Write-Host "==> zipping"
$zip = Join-Path $dist "emsign-trust-check-$Version-windows-x64.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal

Write-Host ""
Write-Host "artifact: $zip"
Get-ChildItem $dist | Select-Object Name, Length, LastWriteTime | Format-Table -Auto
