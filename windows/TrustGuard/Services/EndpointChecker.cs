using Microsoft.Win32;
using TrustGuard.Models;

namespace TrustGuard.Services;

/// <summary>
/// Endpoint checks: only the two items that matter for day-to-day operations —
/// official security patch level and firewall state. Everything runs locally.
/// </summary>
public static class EndpointChecker
{
    public static IEnumerable<CheckResult> CreateChecks()
    {
        yield return new CheckResult
        {
            Id = "h-patch",
            Category = "系统与补丁",
            Title = "官方安全补丁状态",
            Severity = Severity.Critical,
            Impact = "长期不装官方安全补丁的终端，是勒索软件与横向渗透的首选跳板：攻击者可以直接利用已公开的漏洞拿到系统权限，而这类攻击不需要用户点击任何附件。内网一旦被横向移动，影响面会从单台终端扩大到整个业务网段。",
            Fix = "对内网终端，在一台可上网的电脑上下载对应版本的 Windows 累积更新（.msu），拷入内网逐台安装；Windows 10 已结束支持的机器应升级到 Windows 11 或购买 ESU。装完后重新检测，确认最近更新日期已刷新。"
        };

        yield return new CheckResult
        {
            Id = "h-firewall",
            Category = "网络暴露面",
            Title = "防火墙开闭状态",
            Severity = Severity.High,
            Impact = "防火墙关闭时，终端会把 445、3389、135 等端口直接暴露给整个网络，蠕虫式传播可在短时间内扩散到大量机器；这类端口也是勒索病毒和横向移动工具最先探测的目标。",
            Fix = "在「Windows 安全中心 → 防火墙和网络保护」中启用域、专用、公用三个配置文件；如需放行业务端口，用组策略或防火墙规则精确放行，不要整体关闭防火墙。"
        };
    }

    public static async Task RunAllAsync(IEnumerable<CheckResult> checks, IProgress<CheckResult> progress)
    {
        var list = checks.ToList();
        foreach (var c in list) { c.Status = CheckStatus.Running; progress.Report(c); }

        await Task.Run(() =>
        {
            foreach (var check in list)
            {
                try
                {
                    switch (check.Id)
                    {
                        case "h-patch": CheckPatch(check); break;
                        case "h-firewall": CheckFirewall(check); break;
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

    private static void CheckPatch(CheckResult c)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var product = key?.GetValue("ProductName") as string ?? "Windows";
        var display = key?.GetValue("DisplayVersion") as string ?? "";
        var edition = key?.GetValue("EditionID") as string ?? "";
        var buildStr = key?.GetValue("CurrentBuildNumber") as string ?? "0";
        var ubr = key?.GetValue("UBR")?.ToString() ?? "0";
        int.TryParse(buildStr, out var build);

        var os = $"{product} {display} (Build {build}.{ubr})";
        var isLtsc = edition.StartsWith("EnterpriseS", StringComparison.OrdinalIgnoreCase) ||
                     product.Contains("LTSC", StringComparison.OrdinalIgnoreCase) ||
                     product.Contains("LTSB", StringComparison.OrdinalIgnoreCase);

        // 1) Is the OS itself still receiving official patches?
        var supported = true;
        var supportNote = "";
        if (build >= 22000)
        {
            supportNote = "受支持的 Windows 11 版本";
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
            if (daysLeft >= 0)
            {
                supportNote = $"{name}，官方支持至 {eol:yyyy-MM-dd}";
                if (daysLeft <= 90) supportNote += $"（剩余 {daysLeft} 天，请提前规划升级）";
            }
            else
            {
                supported = false;
                supportNote = $"{name} 已于 {eol:yyyy-MM-dd} 结束支持";
            }
        }
        else if (build >= 19041)
        {
            supported = false;
            supportNote = "Windows 10 已于 2025-10-14 结束支持，不再提供官方安全更新";
        }
        else
        {
            supported = false;
            supportNote = "系统版本过旧，已停止支持";
        }

        // 2) When was the last official update installed?
        var ps = Shell.PowerShell(@"
$h = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($h) { '{0}|{1}' -f $h.HotFixID, $h.InstalledOn.ToString('yyyy-MM-dd') } else { 'NONE|' }
", 30000).Trim();
        var parts = ps.Split('|');
        var installed = DateTime.MinValue;
        var hasHotfix = parts.Length >= 2 && parts[0] != "NONE" && DateTime.TryParse(parts[1], out installed);
        var days = hasHotfix ? (int)(DateTime.Now - installed).TotalDays : -1;

        var lastUpdate = hasHotfix
            ? $"最近一次官方更新 {parts[0]}，安装于 {installed:yyyy-MM-dd}（{days} 天前）"
            : "未读取到已安装更新记录";

        if (!supported)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"{os} — {supportNote}。{lastUpdate}。";
        }
        else if (!hasHotfix)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = $"{os} — {supportNote}，但{lastUpdate}，无法确认补丁是否完整。";
        }
        else if (days > 120)
        {
            c.Status = CheckStatus.Fail;
            c.Detail = $"{os} — {supportNote}。{lastUpdate}，已明显滞后于官方更新节奏。";
        }
        else if (days > 45)
        {
            c.Status = CheckStatus.Warn;
            c.Detail = $"{os} — {supportNote}。{lastUpdate}，建议尽快安装最新累积更新。";
        }
        else
        {
            c.Status = CheckStatus.Pass;
            c.Detail = $"{os} — {supportNote}。{lastUpdate}，补丁状态正常。";
        }
        c.Evidence = $"build={build}.{ubr}, edition={edition}, supported={supported}, lastHotfix={(hasHotfix ? parts[0] : "none")}, ageDays={days}";
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
            c.Detail = "无法读取防火墙配置，请以管理员身份重新检测。";
            return;
        }

        var disabled = lines.Where(l => l.EndsWith("|False", StringComparison.OrdinalIgnoreCase)).ToList();
        if (disabled.Count == 0)
        {
            c.Status = CheckStatus.Pass;
            c.Detail = "域、专用、公用三个防火墙配置文件均已开启。";
        }
        else
        {
            c.Status = CheckStatus.Fail;
            c.Detail = "以下防火墙配置文件处于关闭状态：" + string.Join("、", disabled.Select(l => l.Split('|')[0])) + "。";
        }
        c.Evidence = string.Join("\n", lines);
    }
}
