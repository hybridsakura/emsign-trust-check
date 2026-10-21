using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TrustGuard.Models;

namespace TrustGuard.Services;

/// <summary>
/// Hospital-oriented risk checks. All checks work offline; nothing is uploaded.
/// Machine profiles: intranet PC / Internet-facing PC / USB-only air-gapped PC / BYOD laptop.
/// </summary>
public static class HospitalChecker
{
    private static readonly HashSet<MachineProfile> Portable = new()
        { MachineProfile.Byod, MachineProfile.InternetFacing };

    public static IEnumerable<CheckResult> CreateChecks()
    {
        yield return new CheckResult
        {
            Id = "h-os",
            Category = "系统与补丁",
            Title = "操作系统版本与支持状态",
            Severity = Severity.Critical,
            RelevanceHint = "Windows 10 已于 2025-10-14 结束支持",
            Impact = "医院终端若停留在已停止支持的 Windows 10，将不再获得任何安全补丁；一旦被利用（如勒索软件横向移动），HIS/LIS/PACS 业务可能整体瘫痪，且等保测评直接不通过。",
            Fix = "升级到 Windows 11 或购买 Windows 10 ESU；无法升级的医疗设备专用机应做网络隔离与白名单管控。"
        };
        yield return new CheckResult
        {
            Id = "h-patch",
            Category = "系统与补丁",
            Title = "最近一次安全更新距今时间",
            Severity = Severity.High,
            Impact = "长期不装补丁的终端是勒索病毒与横向渗透的首选跳板。医院内网一旦被横向移动，影响面从单台电脑扩大到全院业务系统；断网优盘机则可能把病毒通过 U 盘带入隔离区。",
            Fix = "内网机器通过 WSUS/离线补丁包保持季度内更新；外网机器开启自动更新；断网机建立离线补丁与病毒库更新流程。"
        };
        yield return new CheckResult
        {
            Id = "h-defender",
            Category = "防护与更新",
            Title = "杀毒软件与病毒库状态",
            Severity = Severity.Critical,
            Impact = "医院终端缺少实时防护或病毒库过期时，U 盘摆渡、钓鱼邮件附件、共享目录投毒都可能直接落地执行，进而加密病历文件或窃取患者信息。",
            Fix = "确保 Windows Defender 实时保护开启且病毒库 7 天内更新；使用第三方 EDR 的终端应确认其服务与驱动正常运行。"
        };
        yield return new CheckResult
        {
            Id = "h-firewall",
            Category = "网络暴露面",
            Title = "Windows 防火墙配置文件状态",
            Severity = Severity.High,
            Impact = "防火墙关闭的终端会把 445/3389/135 等端口直接暴露给全院网络，蠕虫式传播（如永恒之蓝类）可一夜之间扩散。",
            Fix = "启用域/专用/公用三个配置文件的防火墙；由组策略统一下发例外规则，禁止逐台手工关闭。"
        };
        yield return new CheckResult
        {
            Id = "h-rdp",
            Category = "网络暴露面",
            Title = "远程桌面（RDP）暴露情况",
            Severity = Severity.High,
            Impact = "医院内网大量终端开启 3389 且使用弱口令时，极易被暴力破解后作为跳板进入 HIS 网段，是近年医院勒索事件最常见的入口之一。",
            Fix = "非必要关闭远程桌面；必须使用时启用网络级身份验证（NLA）、限制来源 IP、使用强口令并纳入堡垒机审计。"
        };
        yield return new CheckResult
        {
            Id = "h-smb1",
            Category = "网络暴露面",
            Title = "SMBv1 与文件共享签名",
            Severity = Severity.Critical,
            Impact = "SMBv1 是永恒之蓝/勒索蠕虫的主要传播通道；未强制 SMB 签名还会让攻击者通过 NTLM 中继窃取凭证，进而控制影像、检验等共享服务器。",
            Fix = "禁用 SMBv1（含客户端与服务端）；在文件服务器与终端上启用 SMB 签名（RequireSecuritySignature）。"
        };
        yield return new CheckResult
        {
            Id = "h-print",
            Category = "网络暴露面",
            Title = "打印服务与 Point-and-Print 策略",
            Severity = Severity.High,
            Impact = "医院普遍部署共享打印/自助报告机，Print Spooler 相关漏洞（PrintNightmare 类）可让普通用户以 SYSTEM 权限执行代码，直接获取终端控制权。",
            Fix = "关闭非必需终端上的 Print Spooler 服务；启用 PointAndPrint 的 RestrictDriverInstallationToAdministrators=1 并限制驱动服务器。"
        };
        yield return new CheckResult
        {
            Id = "h-accounts",
            Category = "身份与访问",
            Title = "账户与口令策略",
            Severity = Severity.High,
            Impact = "Guest 启用、无锁定阈值、口令长度不足，会让攻击者用简单字典爆破进入工作站，进而接触病历与医保结算数据。",
            Fix = "禁用 Guest 与内置 Administrator；口令长度 ≥ 8 且启用复杂度；账户锁定阈值 ≤ 5 次；定期清理离职人员账号。"
        };
        yield return new CheckResult
        {
            Id = "h-shares",
            Category = "身份与访问",
            Title = "本机共享目录暴露",
            Severity = Severity.Medium,
            Impact = "科室自建共享往往权限过宽（Everyone 可读写），勒索病毒可直接加密共享内容，患者资料也可能被任意调阅。",
            Fix = "清理非必要共享；必须共享时按岗位最小权限授权，禁用 Everyone 写权限，并纳入备份与审计。"
        };
        yield return new CheckResult
        {
            Id = "h-usb",
            Category = "外设与介质",
            Title = "USB 存储与自动播放策略",
            Severity = Severity.High,
            RelevanceHint = "U 盘摆渡是断网区主要感染途径",
            Impact = "允许任意 U 盘读写且开启自动播放时，摆渡病毒可在断网优盘机之间传播；医院检验、影像科室的离线设备常因此成为盲区。",
            Fix = "通过组策略将可移动存储设为只读或禁用；关闭自动播放；保留经审批的专用摆渡 U 盘并做病毒扫描。"
        };
        yield return new CheckResult
        {
            Id = "h-legacy",
            Category = "协议与凭据",
            Title = "遗留协议与凭据保护（TLS 1.0/WDigest/NTLM）",
            Severity = Severity.High,
            Impact = "启用 TLS 1.0/1.1、WDigest 明文缓存凭据或允许 NTLMv1，会让攻击者在同网段嗅探到域账号口令，直接威胁 HIS 域环境。",
            Fix = "禁用 TLS 1.0/1.1 与 SSL；设置 WDigest UseLogonCredential=0；LmCompatibilityLevel ≥ 5（仅发送 NTLMv2 并拒绝 LM）。"
        };
        yield return new CheckResult
        {
            Id = "h-remote",
            Category = "第三方软件",
            Title = "远程控制软件安装情况",
            Severity = Severity.Medium,
            Impact = "未经授权的 TeamViewer / 向日葵 / ToDesk 等远控工具可绕过边界防护直接操作院内终端，是患者数据外泄与勒索投毒的常见通道。",
            Fix = "卸载非授权远控软件；确需远程运维时使用堡垒机或院内统一的运维通道，并保留审计日志。"
        };
        yield return new CheckResult
        {
            Id = "h-bitlocker",
            Category = "终端与数据",
            Title = "磁盘加密（BitLocker）状态",
            Severity = Severity.High,
            RelevantProfiles = Portable,
            Impact = "自带笔记本或移动工作站遗失、被带离医院时，未加密磁盘上的病历缓存、导出报表可被直接读取，构成患者隐私泄露事件。",
            Fix = "对笔记本与移动终端启用 BitLocker（含 TPM+PIN），恢复密钥托管到 AD/院内密钥库。"
        };
        yield return new CheckResult
        {
            Id = "h-identity",
            Category = "终端与数据",
            Title = "域加入与终端纳管状态",
            Severity = Severity.Medium,
            RelevanceHint = "自带设备接入医院网络需纳管",
            Impact = "未加入域、未纳入 MDM/终端管理系统的设备接入医院网络后，补丁、杀毒、外设策略均无法统一管控，成为合规与安全的双重盲区。",
            Fix = "院内终端统一加域并由组策略管理；BYOD 设备接入前完成登记、安装 EDR 并划分到隔离 VLAN。"
        };
        yield return new CheckResult
        {
            Id = "h-updatesource",
            Category = "系统与补丁",
            Title = "补丁来源与更新通道",
            Severity = Severity.Medium,
            Impact = "断网或半隔离终端没有可用更新源时，系统与病毒库会持续落后；医院常见「内网 WSUS 未覆盖」导致补丁断层。",
            Fix = "部署院内 WSUS/离线更新服务器并覆盖全部网段；断网区建立定期离线补丁与病毒库导入流程。"
        };
        yield return new CheckResult
        {
            Id = "h-network",
            Category = "网络暴露面",
            Title = "互联网可达性（终端定位）",
            Severity = Severity.Low,
            Impact = "用于区分外网终端与纯内网/断网终端：可达互联网的机器面临钓鱼与外部扫描风险，不可达的机器主要风险来自 U 盘摆渡与内部横向移动，处置策略不同。",
            Fix = "按终端定位套用对应策略：外网机强化浏览器与邮件防护，内网机强化横向移动防护与介质管控。"
        };
    }

    public static async Task RunAllAsync(IEnumerable<CheckResult> checks, IProgress<CheckResult> progress)
    {
        foreach (var c in checks) { c.Status = CheckStatus.Running; progress.Report(c); }

        await Task.Run(() =>
        {
            foreach (var check in checks)
            {
                try
                {
                    switch (check.Id)
                    {
                        case "h-os": CheckOs(check); break;
                        case "h-patch": CheckPatch(check); break;
                        case "h-defender": CheckDefender(check); break;
                        case "h-firewall": CheckFirewall(check); break;
                        case "h-rdp": CheckRdp(check); break;
                        case "h-smb1": CheckSmb(check); break;
                        case "h-print": CheckPrint(check); break;
                        case "h-accounts": CheckAccounts(check); break;
                        case "h-shares": CheckShares(check); break;
                        case "h-usb": CheckUsb(check); break;
                        case "h-legacy": CheckLegacy(check); break;
                        case "h-remote": CheckRemoteTools(check); break;
                        case "h-bitlocker": CheckBitLocker(check); break;
                        case "h-identity": CheckIdentity(check); break;
                        case "h-updatesource": CheckUpdateSource(check); break;
                        case "h-network": CheckNetwork(check); break;
                        default:
                            check.Status = CheckStatus.Info;
                            check.Detail = "未实现的检查项。";
                            break;
                    }
                }
                catch (Exception ex)
                {
                    check.Status = CheckStatus.Warn;
                    check.Detail = "检测异常：" + ex.Message;
                }
                progress.Report(check);
            }
        });
    }

    // ------------------------------------------------------------------
    // individual checks
    // ------------------------------------------------------------------

    private static void CheckOs(CheckResult c)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var product = key?.GetValue("ProductName") as string ?? "Windows";
        var display = key?.GetValue("DisplayVersion") as string ?? "";
        var buildStr = key?.GetValue("CurrentBuildNumber") as string ?? "0";
        var ubr = key?.GetValue("UBR")?.ToString() ?? "0";
        int.TryParse(buildStr, out var build);

        var os = $"{product} {display} (Build {build}.{ubr})";
        var edition = key?.GetValue("EditionID") as string ?? "";
        var isLtsc = edition.StartsWith("EnterpriseS", StringComparison.OrdinalIgnoreCase) ||
                     product.Contains("LTSC", StringComparison.OrdinalIgnoreCase) ||
                     product.Contains("LTSB", StringComparison.OrdinalIgnoreCase);

        if (build >= 22000)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = $"{os} — 受支持的 Windows 11 版本。";
        }
        else if (isLtsc)
        {
            var (eol, name) = build switch
            {
                19044 => (new DateTime(2027, 1, 12), "Windows 10 Enterprise LTSC 2021"),
                17763 => (new DateTime(2029, 1, 9), "Windows 10 Enterprise LTSC 2019"),
                14393 => (new DateTime(2026, 10, 13), "Windows 10 Enterprise LTSB 2016"),
                _ => (new DateTime(2025, 10, 14), "Windows 10 LTSB/LTSC")
            };
            var daysLeft = (int)(eol - DateTime.Today).TotalDays;
            if (daysLeft > 90)
            {
                c.Status = CheckStatus.Pass;
                c.Detail = $"{os} — {name} 属于长期服务版，支持至 {eol:yyyy-MM-dd}（剩余 {daysLeft} 天）。请提前规划升级。";
            }
            else if (daysLeft >= 0)
            {
                c.Status = CheckStatus.Warn;
                c.Detail = $"{os} — {name} 将于 {eol:yyyy-MM-dd} 结束支持（剩余 {daysLeft} 天），请尽快制定升级计划。";
            }
            else
            {
                c.Status = CheckStatus.Fail;
                c.Detail = $"{os} — {name} 已于 {eol:yyyy-MM-dd} 结束支持，不再获得安全更新。";
            }
        }
        else if (build >= 19041)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"{os} — Windows 10 已于 2025-10-14 结束支持，不再获得安全更新。";
        }
        else
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"{os} — 版本过旧，已停止支持。";
        }
        c.Evidence = os + $" | EditionID={edition}";
    }

    private static void CheckPatch(CheckResult c)
    {
        var output = Shell.PowerShell(@"
$h = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($h) { '{0}|{1}' -f $h.HotFixID, $h.InstalledOn.ToString('yyyy-MM-dd') } else { 'NONE|' }
", 30000).Trim();

        var parts = output.Split('|');
        if (parts.Length < 2 || parts[0] == "NONE")
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "未读取到已安装更新记录（可能为精简系统或 WMI 被禁用）。";
            return;
        }
        if (!DateTime.TryParse(parts[1], out var date))
        {
            c.Status = CheckStatus.Warn;
            c.Detail = $"最近更新：{parts[0]}，安装日期无法解析。";
            return;
        }
        var days = (int)(DateTime.Now - date).TotalDays;
        c.Status = days <= 45 ? CheckStatus.Pass : days <= 120 ? CheckStatus.Warn : CheckStatus.Fail;
        c.Detail = $"最近一次更新 {parts[0]}，安装于 {date:yyyy-MM-dd}（{days} 天前）。" +
                   (days > 120 ? " 补丁严重滞后。" : days > 45 ? " 建议尽快更新。" : "");
        c.Evidence = $"lastHotfix={parts[0]}, installedOn={date:yyyy-MM-dd}, ageDays={days}";
    }

    private static void CheckDefender(CheckResult c)
    {
        var ps = Shell.PowerShell(@"
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
  'MP|{0}|{1}|{2}|{3}' -f $mp.AntivirusEnabled, $mp.RealTimeProtectionEnabled, $mp.AntivirusSignatureAge, $mp.AntivirusSignatureVersion
} else { 'MP|' }
$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
if ($av) { foreach ($a in $av) { 'AV|' + $a.displayName + '|' + $a.productState } }
", 30000);

        var mpLine = ps.Split('\n').FirstOrDefault(l => l.StartsWith("MP|"))?.Trim();
        var avLines = ps.Split('\n').Where(l => l.StartsWith("AV|")).Select(l => l.Trim()).ToList();

        if (mpLine is null || mpLine == "MP|")
        {
            c.Status = CheckStatus.Warn;
            c.Detail = avLines.Count > 0
                ? "未检测到 Windows Defender 状态，已安装：" + string.Join("；", avLines.Select(x => x.Split('|')[1]))
                : "未检测到杀毒软件信息。";
            c.Evidence = ps;
            return;
        }

        var f = mpLine.Split('|');
        var enabled = f.Length > 1 && f[1].Equals("True", StringComparison.OrdinalIgnoreCase);
        var rtp = f.Length > 2 && f[2].Equals("True", StringComparison.OrdinalIgnoreCase);
        var sigAge = f.Length > 3 && int.TryParse(f[3], out var a) ? a : -1;

        if (!enabled || !rtp)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"Defender 未启用（杀毒：{enabled}，实时保护：{rtp}）。";
        }
        else if (sigAge > 7)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"Defender 实时保护已开启，但病毒库已 {sigAge} 天未更新。";
        }
        else if (sigAge >= 0)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = $"Defender 实时保护开启，病毒库 {sigAge} 天前更新。";
        }
        else
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "Defender 实时保护开启。";
        }
        var thirdParty = avLines
            .Select(x => x.Split('|'))
            .Where(p => p.Length > 1 && !p[1].Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
            .Select(p => p[1])
            .Distinct()
            .ToList();
        if (thirdParty.Count > 0)
            c.Detail += " 同时检测到第三方杀毒：" + string.Join("；", thirdParty) + "。";
        c.Evidence = mpLine + (thirdParty.Count > 0 ? "\n" + string.Join("\n", thirdParty) : "");
    }

    private static void CheckFirewall(CheckResult c)
    {
        var ps = Shell.PowerShell(@"
Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}' -f $_.Name, $_.Enabled }
", 20000);
        var lines = ps.Split('\n').Select(l => l.Trim()).Where(l => l.Contains('|')).ToList();
        if (lines.Count == 0)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "无法读取防火墙配置。";
            return;
        }
        var disabled = lines.Where(l => l.EndsWith("|False", StringComparison.OrdinalIgnoreCase)).ToList();
        c.Status = disabled.Count == 0 ? CheckStatus.Pass : CheckStatus.Fail;
        c.Detail = disabled.Count == 0
            ? "域/专用/公用三个防火墙配置文件均已启用。"
            : "以下防火墙配置文件已关闭：" + string.Join("、", disabled.Select(l => l.Split('|')[0]));
        c.Evidence = string.Join("\n", lines);
    }

    private static void CheckRdp(CheckResult c)
    {
        using var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
        var deny = ts?.GetValue("fDenyTSConnections") is int d ? d : 1;
        using var tds = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
        var nla = tds?.GetValue("UserAuthentication") is int n ? n : 1;
        var listening = IsListening(3389);

        if (deny == 1 && !listening)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "远程桌面已关闭，3389 未监听。";
        }
        else if (deny == 0 && nla == 0)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"远程桌面已开启且未启用 NLA（3389 监听：{listening}）。";
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = $"远程桌面已开启（NLA：{(nla == 1 ? "已启用" : "未启用")}，3389 监听：{listening}）。请确认来源限制与强口令。";
        }
        c.Evidence = $"fDenyTSConnections={deny}, NLA={nla}, listening3389={listening}";
    }

    private static void CheckSmb(CheckResult c)
    {
        var ps = Shell.PowerShell(@"
$cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($cfg) { 'SMB|' + $cfg.EnableSMB1Protocol + '|' + $cfg.RequireSecuritySignature } else { 'SMB|NA|NA' }
", 25000);
        var line = ps.Split('\n').Select(x => x.Trim()).FirstOrDefault(x => x.StartsWith("SMB|")) ?? "SMB|NA|NA";
        var f = line.Split('|');

        bool smb1Enabled;
        bool signRequired;
        var source = "Get-SmbServerConfiguration";
        if (f.Length >= 3 && (f[1] is "True" or "False"))
        {
            smb1Enabled = f[1] == "True";
            signRequired = f[2] == "True";
        }
        else
        {
            source = "registry (fallback)";
            using var srv = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            smb1Enabled = srv?.GetValue("SMB1") is int s && s == 1;
            signRequired = srv?.GetValue("RequireSecuritySignature") is int r && r == 1;
        }

        if (smb1Enabled)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = "SMBv1 已启用（勒索蠕虫主要传播通道）" + (signRequired ? "，SMB 签名已强制。" : "，且未强制 SMB 签名。");
        }
        else if (!signRequired)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "SMBv1 已禁用，但未强制 SMB 签名，存在 NTLM 中继窃取凭证风险。";
        }
        else
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "SMBv1 已禁用，且已强制 SMB 签名。";
        }
        c.Evidence = $"source={source}, {line}";
    }

    private static void CheckPrint(CheckResult c)
    {
        var spooler = ServiceStatus("Spooler");
        var restrict = ReadInt(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint",
            "RestrictDriverInstallationToAdministrators", -1);

        if (spooler is null)
        {
            c.Status = CheckStatus.Info;
            c.Detail = "未检测到打印服务。";
            return;
        }
        var running = spooler.Equals("Running", StringComparison.OrdinalIgnoreCase);
        if (running && restrict != 1)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "打印服务正在运行，且未限制普通用户安装打印驱动（PrintNightmare 类风险）。";
        }
        else if (running)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "打印服务正在运行（已限制驱动安装，风险降低，但仍建议仅共享打印服务器保留该服务）。";
        }
        else
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "打印服务未运行，不受 Print Spooler 漏洞影响。";
        }
        c.Evidence = $"spooler={spooler}, RestrictDriverInstallationToAdministrators={restrict}";
    }

    private static void CheckAccounts(CheckResult c)
    {
        var cfg = Path.Combine(Path.GetTempPath(), "tg_sec_" + Guid.NewGuid().ToString("N") + ".inf");
        try
        {
            Shell.Run("secedit.exe", $"/export /cfg \"{cfg}\" /areas SECURITYPOLICY", 30000);
            if (!File.Exists(cfg))
            {
                c.Status = CheckStatus.Info;
                c.Detail = "读取账户策略需要管理员权限，请点击右上角「以管理员身份重启」后重新检测。";
                return;
            }
            var text = File.ReadAllText(cfg);
            var minPwd = MatchInt(text, @"MinimumPasswordLength\s*=\s*(\d+)", 0);
            var lockout = MatchInt(text, @"LockoutBadCount\s*=\s*(\d+)", 0);
            var complexity = MatchInt(text, @"PasswordComplexity\s*=\s*(\d+)", 0);

            var guest = GetLocalUserEnabled("Guest");
            var admin = GetLocalUserEnabled("Administrator");

            var problems = new List<string>();
            if (lockout == 0) problems.Add("账户锁定阈值为 0（不会锁定）");
            if (minPwd < 8) problems.Add($"最小口令长度 {minPwd} 位（建议 ≥ 8）");
            if (complexity == 0) problems.Add("未启用口令复杂度");
            if (guest == true) problems.Add("Guest 账户处于启用状态");
            if (admin == true) problems.Add("内置 Administrator 处于启用状态");

            if (problems.Count == 0)
            {
                c.Status = CheckStatus.Pass;
                c.Detail = $"口令长度 {minPwd}，锁定阈值 {lockout}，复杂度已启用，Guest/Administrator 均已禁用。";
            }
            else
            {
                c.Status = problems.Count >= 2 ? CheckStatus.Fail : CheckStatus.Warn;
                c.Detail = string.Join("；", problems) + "。";
            }
            c.Evidence = $"MinimumPasswordLength={minPwd}, LockoutBadCount={lockout}, PasswordComplexity={complexity}, GuestEnabled={guest}, AdministratorEnabled={admin}";
        }
        finally
        {
            try { File.Delete(cfg); } catch { }
        }
    }

    private static void CheckShares(CheckResult c)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares");
        if (key is null)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "未发现本机共享配置。";
            return;
        }
        var names = key.GetValueNames()
            .Where(n => n.EndsWith("$") == false)
            .Where(n => !n.Equals("Shares", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (names.Count == 0)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "仅存在系统默认管理共享，无自定义共享目录。";
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = $"存在 {names.Count} 个自定义共享：" + string.Join("、", names) + "。请确认已按最小权限授权。";
            c.Evidence = string.Join("\n", names);
        }
    }

    private static void CheckUsb(CheckResult c)
    {
        var usbstor = ReadInt(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start", 3);
        var denyAll = ReadInt(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",
            "Deny_All", 0);
        var autorun = ReadInt(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0);
        var autorunDisabled = (autorun & 0x04) != 0;

        var usbBlocked = usbstor == 4 || denyAll == 1;
        if (usbBlocked && autorunDisabled)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "USB 存储已禁用或只读策略生效，且已关闭可移动介质自动播放。";
        }
        else if (!usbBlocked)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "USB 存储可自由读写" + (autorunDisabled ? "（自动播放已关闭）。" : "，且自动播放未完全关闭，U 盘摆渡风险较高。");
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "USB 存储已管控，但自动播放未完全关闭。";
        }
        c.Evidence = $"USBSTOR.Start={usbstor}, Deny_All={denyAll}, NoDriveTypeAutoRun=0x{autorun:X}";
    }

    private static void CheckLegacy(CheckResult c)
    {
        var tls10 = ReadInt(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "Enabled", 0);
        var tls11 = ReadInt(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "Enabled", 0);
        var wdigest = ReadInt(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0);
        var lm = ReadInt(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 3);

        var problems = new List<string>();
        if (tls10 == 1) problems.Add("TLS 1.0 服务端已启用");
        if (tls11 == 1) problems.Add("TLS 1.1 服务端已启用");
        if (wdigest == 1) problems.Add("WDigest 明文缓存登录凭据");
        if (lm < 3) problems.Add($"NTLM 兼容级别过低（{lm}）");

        if (problems.Count == 0)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "未启用 TLS 1.0/1.1，WDigest 未缓存明文口令，NTLM 级别符合要求。";
        }
        else
        {
            c.Status = problems.Count >= 2 ? CheckStatus.Fail : CheckStatus.Warn;
            c.Detail = string.Join("；", problems) + "。";
        }
        c.Evidence = $"TLS1.0={tls10}, TLS1.1={tls11}, WDigest={wdigest}, LmCompatibilityLevel={lm}";
    }

    private static void CheckRemoteTools(CheckResult c)
    {
        var patterns = new[] { "TeamViewer", "AnyDesk", "向日葵", "Sunlogin", "ToDesk", "AweSun", "GotoHTTP", "Radmin", "VNC", "LogMeIn", "Splashtop", "RustDesk" };
        var found = new List<string>();
        foreach (var sub in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                using var key = hive.OpenSubKey(sub);
                if (key is null) continue;
                foreach (var name in key.GetSubKeyNames())
                {
                    using var app = key.OpenSubKey(name);
                    var display = app?.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(display)) continue;
                    if (patterns.Any(p => display.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        found.Add(display);
                }
            }
        }
        found = found.Distinct().ToList();
        if (found.Count == 0)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "未发现常见的第三方远程控制软件。";
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "检测到远程控制软件：" + string.Join("；", found) + "。请确认是否经授权并纳入运维审计。";
            c.Evidence = string.Join("\n", found);
        }
    }

    private static void CheckBitLocker(CheckResult c)
    {
        var ps = Shell.PowerShell(@"
try {
  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  'OK|' + $v.ProtectionStatus + '|' + $v.VolumeStatus
} catch { 'ERR' }
", 25000).Trim();

        if (!ps.StartsWith("OK|"))
        {
            c.Status = CheckStatus.Info;
            c.Detail = "无法读取 BitLocker 状态：需要以管理员身份运行本程序（或其系统版本不支持 BitLocker）。";
            return;
        }
        var f = ps.Split('|');
        var protection = f[1];
        if (protection.Equals("On", StringComparison.OrdinalIgnoreCase))
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "系统盘已启用 BitLocker 加密。";
        }
        else
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"系统盘未加密（保护状态：{protection}）。便携设备遗失时数据可被直接读取。";
        }
        c.Evidence = ps;
    }

    private static void CheckIdentity(CheckResult c)
    {
        var ps = Shell.PowerShell(@"
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs) { 'DOMAIN|{0}|{1}' -f $cs.PartOfDomain, $cs.Domain } else { 'DOMAIN|False|' }
$mdm = Test-Path 'HKLM:\SOFTWARE\Microsoft\Enrollments'
'MDM|' + $mdm
", 20000);
        var domainLine = ps.Split('\n').Select(x => x.Trim()).FirstOrDefault(x => x.StartsWith("DOMAIN|")) ?? "DOMAIN|False|";
        var parts = domainLine.Split('|');
        var joined = parts.Length > 1 && parts[1].Equals("True", StringComparison.OrdinalIgnoreCase);
        var domain = parts.Length > 2 ? parts[2] : "";

        if (joined)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = $"已加入域：{domain}，可受组策略统一管控。";
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "未加入域（工作组模式），补丁、杀毒与外设策略无法统一管控。BYOD 设备接入院内网络前应完成登记与纳管。";
        }
        c.Evidence = ps;
    }

    private static void CheckUpdateSource(CheckResult c)
    {
        var wsus = ReadString(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer");
        var auOptions = ReadInt(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", "AUOptions", -1);

        var online = Probe("223.5.5.5", 443);
        if (!string.IsNullOrWhiteSpace(wsus))
        {
            c.Status = CheckStatus.Pass;
            c.Detail = $"已配置院内更新源（WSUS）：{wsus}。";
        }
        else if (auOptions is 3 or 4)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "使用 Windows 自动更新（直接连接微软更新服务器）。";
        }
        else if (online)
        {
            c.Status = CheckStatus.Info;
            c.Detail = "未配置统一更新源，使用系统默认更新策略（本机可访问互联网）。医院环境建议改为院内 WSUS 统一管控。";
        }
        else
        {
            c.Status = CheckStatus.Warn;
            c.Detail = "未配置 WSUS 且本机无外网，系统将长期无法获得补丁；需建立离线补丁导入流程。";
        }
        c.Evidence = $"WUServer={wsus ?? "(none)"}, AUOptions={auOptions}";
    }

    private static void CheckNetwork(CheckResult c)
    {
        var online = Probe("223.5.5.5", 443) || Probe("114.114.114.114", 53);
        c.Status = CheckStatus.Info;
        c.Detail = online
            ? "本机可访问互联网 —— 按「外网终端」策略：强化钓鱼邮件、浏览器与外部扫描防护。"
            : "本机无法访问互联网 —— 按「内网/断网终端」策略：重点管控 U 盘摆渡、横向移动与离线补丁。";
        c.Evidence = $"internetReachable={online}";
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static bool Probe(string host, int port)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(2000) && client.Connected;
        }
        catch { return false; }
    }

    private static bool IsListening(int port)
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(ep => ep.Port == port);
        }
        catch { return false; }
    }

    private static string? ServiceStatus(string name)
    {
        var ps = Shell.PowerShell($"try {{ (Get-Service -Name {name} -ErrorAction Stop).Status }} catch {{ 'NA' }}", 20000).Trim();
        return ps is "" or "NA" ? null : ps;
    }

    private static int ReadInt(RegistryKey root, string path, string name, int fallback)
    {
        using var key = root.OpenSubKey(path);
        var v = key?.GetValue(name);
        return v switch
        {
            int i => i,
            long l => (int)l,
            string s when int.TryParse(s, out var p) => p,
            _ => fallback
        };
    }

    private static string? ReadString(RegistryKey root, string path, string name)
    {
        using var key = root.OpenSubKey(path);
        return key?.GetValue(name) as string;
    }

    private static int MatchInt(string text, string pattern, int fallback)
    {
        var m = Regex.Match(text, pattern);
        return m.Success && int.TryParse(m.Groups[1].Value, out var v) ? v : fallback;
    }

    private static bool? GetLocalUserEnabled(string name)
    {
        var ps = Shell.PowerShell($@"
try {{
  $u = Get-CimInstance Win32_UserAccount -Filter ""Name='{name}' AND LocalAccount=True"" -ErrorAction Stop
  if ($u) {{ ($u | Select-Object -First 1).Disabled }} else {{ 'NA' }}
}} catch {{ 'NA' }}
", 20000).Trim();
        if (ps.Equals("True", StringComparison.OrdinalIgnoreCase)) return false;  // Disabled=True -> not enabled
        if (ps.Equals("False", StringComparison.OrdinalIgnoreCase)) return true;
        return null;
    }
}
