# Builds a portable, self-contained TrustGuard.exe (no .NET install required on target PCs)
# and packs a ready-to-distribute folder + zip under ..\dist\.
#
# Variants:
#   Public   (default) - industry-neutral copy, safe to publish
#   Internal           - pulls organisation branding from Branding\InternalBranding.local.cs
#                        (git-ignored) and adds the footer / signature / tech-support line
#
# Requirements on the BUILD machine only: .NET 8 SDK (win-x64).
# Target machines: Windows 10 1607+ / Windows 11, x64. No installer, no runtime needed.

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$Dotnet = "dotnet",
    [ValidateSet("Public", "Internal")]
    [string]$Variant = "Public"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $root "TrustGuard"
$dist = Join-Path (Split-Path -Parent $root) "dist"
$suffix = if ($Variant -eq "Internal") { "-internal" } else { "" }
$stage = Join-Path $dist "TrustGuard-$Version-win-x64$suffix"
$publishDir = Join-Path $proj "publish$suffix"

if ($Variant -eq "Internal") {
    $branding = Join-Path $proj "Branding\InternalBranding.local.cs"
    if (-not (Test-Path $branding)) {
        throw "Internal branding file not found: $branding"
    }
}

Write-Host "==> publishing $Variant build (self-contained single file)"
& $Dotnet publish (Join-Path $proj "TrustGuard.csproj") -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    -p:Variant=$Variant -o $publishDir --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "==> staging distribution folder"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage "scripts") | Out-Null

Copy-Item (Join-Path $publishDir "TrustGuard.exe") $stage
Copy-Item (Join-Path $root "..\public\downloads\Check-EmSignTrust.ps1") (Join-Path $stage "scripts")
Copy-Item (Join-Path $root "..\public\downloads\fingerprints.json") (Join-Path $stage "scripts")
Copy-Item (Join-Path $root "README-Windows.txt") $stage

Write-Host "==> zipping"
$zip = Join-Path $dist "emsign-trust-check-$Version-windows-x64$suffix.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal

Write-Host ""
Write-Host "artifact: $zip"
Get-ChildItem $dist | Where-Object { $_.Name -like "*windows*" } | Select-Object Name, Length, LastWriteTime | Format-Table -Auto
