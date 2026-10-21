<#
.SYNOPSIS
    emSign 证书漏洞本地检测脚本（离线可用）— 仿 emudhra.we-have-a-problem.com 的检测思路。

.DESCRIPTION
    检测当前 Windows 电脑是否仍信任 2026 年 10 月被攻陷的 8 个 eMudhra 中间 CA
    （含 Sectigo 交叉签名，共 16 张证书）。检测分三层：

      1. Windows 吊销列表检查：比对系统「不允许的证书」(Disallowed CTL) 缓存中
         是否已包含 16 张问题证书的指纹（微软 2026-10-20 起推送封锁）。
         该检查覆盖 Edge / Chrome / 系统及所有使用 Schannel 的程序。
      2. 浏览器版本枚举：列出已安装的 Chrome / Edge / Firefox 及版本，
         对照各厂商封锁时间给出风险提示（长期离线机器可能未收到推送）。
      3. 在线 TLS 探测（可选，需外网）：对 12 个测试域名发起真实 TLS 握手，
         连接成功 = 仍信任 = 有风险；证书错误 = 已拦截 = 安全。

    结果输出到控制台，可用 -ExportCsv 导出供内网批量汇总。

.PARAMETER SkipOnline
    跳过在线 TLS 探测（纯内网机器使用）。

.PARAMETER ExportCsv
    将结果导出为 CSV 文件的路径（每台机器一行），便于批量收集汇总。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Check-EmSignTrust.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Check-EmSignTrust.ps1 -SkipOnline -ExportCsv "\\fileserver\share\emsign\results.csv"

.NOTES
    数据来源: https://emudhra.we-have-a-problem.com/impacted-intermediates.json
    证书指纹由 PEM 原文本地计算，SHA256 已与官方清单逐一校验。
#>
[CmdletBinding()]
param(
    [switch]$SkipOnline,
    [string]$ExportCsv
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# 16 张被攻陷证书（8 个中间 CA x 2 条链）的指纹，来源见 .NOTES
# ---------------------------------------------------------------------------
$Compromised = @(
    @{ Name = 'EM DV TLS CA - G3B'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493'; Sha1 = 'A99B289464F3B44343270A7A1E910F02370483FE' }
    @{ Name = 'EM DV TLS CA - G3B'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = '45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE'; Sha1 = '1396BE1372BC93DFA2A433CA964DBA91548A6E57' }
    @{ Name = 'EM OV TLS CA - G3B'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = '98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B'; Sha1 = '5F014E0DB3BB8F950E0598AB280846D383FC57BE' }
    @{ Name = 'EM OV TLS CA - G3B'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = '5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699'; Sha1 = '5DFA19197D1C1CF629AF7C0CD865543C5050227C' }
    @{ Name = 'EM EV TLS CA - G3B'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = 'E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838'; Sha1 = 'F33ACD1F5D31AA81AC18C72C928446226D3D5914' }
    @{ Name = 'EM EV TLS CA - G3B'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = '579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512'; Sha1 = '19069BD6533BFF93FB67C71FB3376B4EA7402C3B' }
    @{ Name = 'EM DV TLS CA - G3C'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = '0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19'; Sha1 = '8AD23BC78845D6FAAE1D534BAC89F0E36BA55A11' }
    @{ Name = 'EM DV TLS CA - G3C'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = '62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72'; Sha1 = '4B0944C14F8C2CCBA4E4F32104AD920FA15EE331' }
    @{ Name = 'EM OV TLS CA - G3C'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = 'CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F'; Sha1 = '7FCC31AAB874CE6C8EE8584F54CFD08646B54117' }
    @{ Name = 'EM OV TLS CA - G3C'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = '7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489'; Sha1 = '305FC1E253DCAB71B95D4995DAE3CB09D562F22A' }
    @{ Name = 'EM EV TLS CA - G3C'; IssuedBy = 'emSign Root TLS CA - G3';    Usage = 'TLS';        Sha256 = '432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3'; Sha1 = 'C988F3D0CC1629FFC43165D6464C9B6EF73D6E48' }
    @{ Name = 'EM EV TLS CA - G3C'; IssuedBy = 'AAA Certificate Services';   Usage = 'TLS';        Sha256 = 'FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F'; Sha1 = '8588708E875A1F8AA83524F3559080F7E17068C7' }
    @{ Name = 'EM OV CS CA - G3B';  IssuedBy = 'emSign Root CS CA - G3';     Usage = 'CodeSigning'; Sha256 = '9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4'; Sha1 = 'D33195A244046A3263FB5E0E83C6803A5B2E7BC3' }
    @{ Name = 'EM OV CS CA - G3B';  IssuedBy = 'AAA Certificate Services';   Usage = 'CodeSigning'; Sha256 = 'A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8'; Sha1 = 'EE26D7AE3CC71718F6E07D7D0095076F0C158F63' }
    @{ Name = 'EM OV CS CA - G3C';  IssuedBy = 'emSign Root CS CA - G3';     Usage = 'CodeSigning'; Sha256 = '4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1'; Sha1 = '1F4A5D178F8B6A8EF0F6784155BD5FEA91158B12' }
    @{ Name = 'EM OV CS CA - G3C';  IssuedBy = 'AAA Certificate Services';   Usage = 'CodeSigning'; Sha256 = '84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD'; Sha1 = '7FDE64753A957B98F172FD2AB0D922551909C7BA' }
)

$TestHosts = @(
    'dv-g3b-emudhra.we-have-a-problem.com', 'dv-g3c-emudhra.we-have-a-problem.com',
    'ov-g3b-emudhra.we-have-a-problem.com', 'ov-g3c-emudhra.we-have-a-problem.com',
    'ev-g3b-emudhra.we-have-a-problem.com', 'ev-g3c-emudhra.we-have-a-problem.com',
    'dv-g3b-aaa-emudhra.we-have-a-problem.com', 'dv-g3c-aaa-emudhra.we-have-a-problem.com',
    'ov-g3b-aaa-emudhra.we-have-a-problem.com', 'ov-g3c-aaa-emudhra.we-have-a-problem.com',
    'ev-g3b-aaa-emudhra.we-have-a-problem.com', 'ev-g3c-aaa-emudhra.we-have-a-problem.com'
)

function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# 第 1 层：Windows 吊销列表（Disallowed CTL）指纹比对
# ---------------------------------------------------------------------------
Write-Section '1. Windows 吊销列表 (Disallowed CTL) 检查'
$ctlStatus = 'Unknown'
$blockedCount = 0
try {
    $ctlRaw = (certutil.exe -store disallowed 2>$null | Out-String)
    if ([string]::IsNullOrWhiteSpace($ctlRaw) -or $ctlRaw -match '0x80070002|Cannot find|找不到') {
        $ctlStatus = 'NoCTL'
        Write-Host '未找到本地 Disallowed CTL 缓存。系统可能从未更新过吊销列表（长期离线机器常见）。' -ForegroundColor Yellow
    } else {
        $norm = ($ctlRaw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        foreach ($c in $Compromised) {
            if ($norm.Contains($c.Sha1) -or $norm.Contains($c.Sha256)) { $blockedCount++ }
        }
        if ($blockedCount -ge 12) {
            $ctlStatus = 'Blocked'
            Write-Host "吊销列表已包含 $blockedCount / $($Compromised.Count) 张问题证书 → 系统信任存储已封锁。" -ForegroundColor Green
        } elseif ($blockedCount -gt 0) {
            $ctlStatus = 'Partial'
            Write-Host "吊销列表仅包含 $blockedCount / $($Compromised.Count) 张问题证书 → 封锁不完整，存在风险。" -ForegroundColor Red
        } else {
            $ctlStatus = 'NotBlocked'
            Write-Host '吊销列表中未找到任何一张问题证书 → 系统信任存储可能仍信任它们，存在风险！' -ForegroundColor Red
        }
    }
} catch {
    Write-Host "无法读取 Disallowed CTL：$($_.Exception.Message)" -ForegroundColor Yellow
}

# 附带检查：问题证书是否被手工导入进了受信任的中间 CA 存储
$suspectInStore = 0
foreach ($store in @('CA', 'ROOT')) {
    try {
        $raw = (certutil.exe -store $store 2>$null | Out-String) -replace '[^0-9A-Fa-f]', ''
        $raw = $raw.ToUpperInvariant()
        foreach ($c in $Compromised) {
            if ($raw.Contains($c.Sha1) -or $raw.Contains($c.Sha256)) {
                $suspectInStore++
                Write-Host "警告：在系统 $store 存储中发现 $($c.Name)（$($c.IssuedBy)）！" -ForegroundColor Red
            }
        }
    } catch { }
}
if ($suspectInStore -eq 0) { Write-Host '系统 CA/ROOT 存储中未发现被手工信任的问题证书。' -ForegroundColor Green }

# ---------------------------------------------------------------------------
# 第 2 层：已安装浏览器版本
# ---------------------------------------------------------------------------
Write-Section '2. 已安装浏览器'
$browsers = @()
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$found = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'Google Chrome|Microsoft Edge|Mozilla Firefox' } |
    Select-Object -Unique DisplayName, DisplayVersion

foreach ($b in $found) {
    $risk = ''
    if ($b.DisplayName -match 'Chrome|Edge') {
        $risk = '封锁依赖 CRLSets / Windows 吊销列表推送（2026-10-17/20 起），长期离线可能未收到'
    } elseif ($b.DisplayName -match 'Firefox') {
        $risk = '封锁依赖 CRLite/OneCRL 推送（2026-10-17 起），长期离线可能未收到'
    }
    $browsers += [pscustomobject]@{ Name = $b.DisplayName; Version = $b.DisplayVersion; Note = $risk }
    Write-Host ("  {0}  {1}  — {2}" -f $b.DisplayName, $b.DisplayVersion, $risk)
}
if (-not $browsers) { Write-Host '  未在注册表中找到 Chrome / Edge / Firefox。' -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# 第 3 层：在线 TLS 探测（curl 使用 Windows Schannel，反映系统信任存储）
# ---------------------------------------------------------------------------
$onlineConnected = -1
if (-not $SkipOnline) {
    Write-Section '3. 在线 TLS 探测（需外网）'
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        Write-Host '  未找到 curl.exe，跳过在线探测。' -ForegroundColor Yellow
    } else {
        $onlineConnected = 0; $onlineBlocked = 0; $onlineTimeout = 0
        foreach ($h in $TestHosts) {
            $null = & curl.exe -s -o NUL --max-time 10 "https://$h/" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $onlineConnected++
                Write-Host "  ❌ $h — 已连接（仍信任！）" -ForegroundColor Red
            } elseif ($LASTEXITCODE -eq 28) {
                $onlineTimeout++
                Write-Host "  ⚠️  $h — 超时，无法确定" -ForegroundColor Yellow
            } else {
                $onlineBlocked++
                Write-Host "  ✅ $h — 证书验证拦截（curl 错误码 $LASTEXITCODE）" -ForegroundColor Green
            }
        }
        Write-Host ("  汇总：已连接 {0} / 被拦截 {1} / 超时 {2}（共 {3} 项）" -f $onlineConnected, $onlineBlocked, $onlineTimeout, $TestHosts.Count)
        if ($onlineTimeout -eq $TestHosts.Count) {
            Write-Host '  全部超时：本机可能无外网访问，在线探测无效，请以前两层结果为准。' -ForegroundColor Yellow
            $onlineConnected = -1
        }
    }
}

# ---------------------------------------------------------------------------
# 汇总结论
# ---------------------------------------------------------------------------
Write-Section '结论'
if ($onlineConnected -gt 0) {
    $verdict = 'VULNERABLE'
    Write-Host "⚠️ 存在风险：在线探测成功连接了 $onlineConnected 个测试站点，本机仍信任被攻陷的 emSign 中间 CA。" -ForegroundColor Red
} elseif ($onlineConnected -eq 0) {
    $verdict = 'PROTECTED'
    Write-Host '✅ 安全：全部测试站点均被证书验证拦截。' -ForegroundColor Green
} elseif ($ctlStatus -eq 'Blocked') {
    $verdict = 'PROTECTED'
    Write-Host '✅ 安全（离线判断）：Windows 吊销列表已封锁全部问题证书。' -ForegroundColor Green
} else {
    $verdict = 'LIKELY-VULNERABLE'
    Write-Host '⚠️ 疑似存在风险（离线判断）：Windows 吊销列表未封锁问题证书。Edge/Chrome/系统组件可能仍信任它们；Firefox 等自带信任存储的浏览器无法离线确认，建议联网后用 index.html 复核。' -ForegroundColor Red
}
Write-Host '建议：尽快安装最新的 Windows 累积更新并更新全部浏览器；详细修复方案见 README.md。'

# ---------------------------------------------------------------------------
# 可选：CSV 导出（每台机器一行，便于批量汇总）
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    $row = [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Verdict        = $verdict
        CTLStatus      = $ctlStatus
        CTLBlocked     = $blockedCount
        SuspectInStore = $suspectInStore
        OnlineConnected= $onlineConnected
        Browsers       = (($browsers | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ')
    }
    $exists = Test-Path $ExportCsv
    $row | Export-Csv -Path $ExportCsv -NoTypeInformation -Append -Encoding UTF8
    Write-Host "`n结果已追加到 $ExportCsv" -ForegroundColor Cyan
}
