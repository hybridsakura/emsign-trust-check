<#
.SYNOPSIS
    离线把 16 张受影响的 eMudhra 中间证书写入 Windows「不信任名单」（Disallowed 存储）。

.DESCRIPTION
    适用于没有 WSUS、没有统一补丁推送、机器长期离线的环境。
    效果等同于微软 2026-10-20 之后通过 Windows 更新下发的 Disallowed CTL：
    写入后，所有使用系统信任库的程序（浏览器、curl、.NET 客户端等）都会拒绝这 16 张证书，
    且断网状态下依然有效。

    脚本完全离线运行，不需要联网，也不改动根证书。

.PARAMETER Remove
    撤销：把这 16 张证书从「不信任名单」中移除（回滚到执行前的状态）。

.PARAMETER Status
    只检查当前状态，不做任何修改（不需要管理员权限）。

.PARAMETER DryRun
    演练：只解析证书并显示将要执行的操作，不写入系统。

.PARAMETER Json
    证书数据文件路径。默认自动在脚本所在目录、public\downloads 等位置查找
    impacted-intermediates.json。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\block-emsign-certs.ps1 -Status

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\block-emsign-certs.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\block-emsign-certs.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Status,
    [switch]$DryRun,
    [string]$Json
)

$ErrorActionPreference = 'Stop'

function Find-Json {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path $Explicit)) { throw "找不到证书数据文件：$Explicit" }
        return (Resolve-Path $Explicit).Path
    }
    $here = $PSScriptRoot
    $candidates = @(
        (Join-Path $here 'impacted-intermediates.json'),
        (Join-Path $here '..\public\downloads\impacted-intermediates.json'),
        (Join-Path $here '..\..\public\downloads\impacted-intermediates.json'),
        (Join-Path $here 'scripts\impacted-intermediates.json'),
        (Join-Path $here '..\scripts\impacted-intermediates.json')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    throw '找不到 impacted-intermediates.json，请用 -Json 指定路径。'
}

function Convert-PemToDer {
    param([string]$Pem)
    $b64 = ($Pem -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '') -replace '\s', ''
    return [Convert]::FromBase64String($b64)
}

function Get-Sha1Hex {
    param([byte[]]$Der)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { return ([BitConverter]::ToString($sha1.ComputeHash($Der))).Replace('-', '') }
    finally { $sha1.Dispose() }
}

function Get-DisallowedHex {
    $raw = (certutil.exe -store Disallowed 2>$null | Out-String)
    if ([string]::IsNullOrWhiteSpace($raw)) { return '' }
    return ($raw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

$jsonPath = Find-Json -Explicit $Json
$certs = Get-Content -Raw -Encoding UTF8 $jsonPath | ConvertFrom-Json
if (-not $certs -or $certs.Count -eq 0) { throw "证书数据为空：$jsonPath" }

$items = @()
foreach ($c in $certs) {
    try {
        $der = Convert-PemToDer -Pem $c.pem
        $items += [pscustomobject]@{
            Name   = $c.name
            Issuer = $c.issuer_operator
            Der    = $der
            Sha1   = Get-Sha1Hex -Der $der
        }
    } catch {
        Write-Host "跳过无法解析的证书：$($c.name)" -ForegroundColor Yellow
    }
}
Write-Host "证书数据：$jsonPath（$($items.Count) 张）" -ForegroundColor Cyan

if ($Status) {
    $hex = Get-DisallowedHex
    $hit = @($items | Where-Object { $hex.Contains($_.Sha1) })
    $color = if ($hit.Count -ge 12) { 'Green' } elseif ($hit.Count -gt 0) { 'Yellow' } else { 'Red' }
    Write-Host ("当前「不信任名单」命中：{0}/{1}" -f $hit.Count, $items.Count) -ForegroundColor $color
    if ($hit.Count -gt 0) { $hit | ForEach-Object { Write-Host ("  - {0}（{1}）" -f $_.Name, $_.Issuer) } }
    exit 0
}

if (-not $DryRun) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '写入系统「不信任名单」需要管理员权限，请右键以管理员身份运行 PowerShell 后重试。'
    }
}

$ok = 0; $fail = 0
foreach ($item in $items) {
    $label = "{0}（{1}）" -f $item.Name, $item.Issuer

    if ($Remove) {
        if ($DryRun) { Write-Host "[演练] 将移除 $label"; $ok++; continue }
        certutil.exe -delstore Disallowed $item.Sha1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "已移除  $label" -ForegroundColor Yellow; $ok++ }
        else { Write-Host "未找到  $label（可能本就不在名单中）" -ForegroundColor DarkGray }
        continue
    }

    if ($DryRun) { Write-Host "[演练] 将导入 $label"; $ok++; continue }

    $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), "emsign-" + [Guid]::NewGuid().ToString('N') + ".cer")
    try {
        [IO.File]::WriteAllBytes($tmp, $item.Der)
        certutil.exe -addstore -f Disallowed $tmp | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "已导入  $label" -ForegroundColor Green; $ok++ }
        else { Write-Host "导入失败 $label（certutil 退出码 $LASTEXITCODE）" -ForegroundColor Red; $fail++ }
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

if ($DryRun) {
    Write-Host "`n演练完成：$ok 项待处理，$fail 项失败。" -ForegroundColor Cyan
    exit 0
}

$hex = Get-DisallowedHex
$hit = @($items | Where-Object { $hex.Contains($_.Sha1) })
Write-Host ("`n处理结果：成功 {0}，失败 {1}；当前名单命中 {2}/{3}" -f $ok, $fail, $hit.Count, $items.Count) -ForegroundColor Cyan

if (-not $Remove -and $hit.Count -lt 12) {
    Write-Host '提示：名单命中少于 12 张，建议重新运行并确认是否被杀软拦截。' -ForegroundColor Yellow
    exit 1
}
exit 0
