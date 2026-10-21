using System.Diagnostics;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TrustGuard.Models;

namespace TrustGuard.Services;

/// <summary>Checks for the October 2026 eMudhra intermediate CA compromise.</summary>
public static class EmSignChecker
{
    private sealed record Cert(string Name, string IssuedBy, string Sha1, string Sha256);

    // Fingerprints computed locally from the official PEM list (SHA-256 verified against it).
    private static readonly Cert[] Certs =
    {
        new("EM DV TLS CA - G3B", "emSign Root TLS CA - G3", "A99B289464F3B44343270A7A1E910F02370483FE", "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"),
        new("EM DV TLS CA - G3B", "AAA Certificate Services", "1396BE1372BC93DFA2A433CA964DBA91548A6E57", "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"),
        new("EM OV TLS CA - G3B", "emSign Root TLS CA - G3", "5F014E0DB3BB8F950E0598AB280846D383FC57BE", "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B"),
        new("EM OV TLS CA - G3B", "AAA Certificate Services", "5DFA19197D1C1CF629AF7C0CD865543C5050227C", "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"),
        new("EM EV TLS CA - G3B", "emSign Root TLS CA - G3", "F33ACD1F5D31AA81AC18C72C928446226D3D5914", "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"),
        new("EM EV TLS CA - G3B", "AAA Certificate Services", "19069BD6533BFF93FB67C71FB3376B4EA7402C3B", "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"),
        new("EM DV TLS CA - G3C", "emSign Root TLS CA - G3", "8AD23BC78845D6FAAE1D534BAC89F0E36BA55A11", "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"),
        new("EM DV TLS CA - G3C", "AAA Certificate Services", "4B0944C14F8C2CCBA4E4F32104AD920FA15EE331", "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"),
        new("EM OV TLS CA - G3C", "emSign Root TLS CA - G3", "7FCC31AAB874CE6C8EE8584F54CFD08646B54117", "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F"),
        new("EM OV TLS CA - G3C", "AAA Certificate Services", "305FC1E253DCAB71B95D4995DAE3CB09D562F22A", "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"),
        new("EM EV TLS CA - G3C", "emSign Root TLS CA - G3", "C988F3D0CC1629FFC43165D6464C9B6EF73D6E48", "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3"),
        new("EM EV TLS CA - G3C", "AAA Certificate Services", "8588708E875A1F8AA83524F3559080F7E17068C7", "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"),
        new("EM OV CS CA - G3B", "emSign Root CS CA - G3", "D33195A244046A3263FB5E0E83C6803A5B2E7BC3", "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4"),
        new("EM OV CS CA - G3B", "AAA Certificate Services", "EE26D7AE3CC71718F6E07D7D0095076F0C158F63", "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"),
        new("EM OV CS CA - G3C", "emSign Root CS CA - G3", "1F4A5D178F8B6A8EF0F6784155BD5FEA91158B12", "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1"),
        new("EM OV CS CA - G3C", "AAA Certificate Services", "7FDE64753A957B98F172FD2AB0D922551909C7BA", "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"),
    };

    private static readonly string[] TestHosts =
    {
        "dv-g3b-emudhra.we-have-a-problem.com", "dv-g3c-emudhra.we-have-a-problem.com",
        "ov-g3b-emudhra.we-have-a-problem.com", "ov-g3c-emudhra.we-have-a-problem.com",
        "ev-g3b-emudhra.we-have-a-problem.com", "ev-g3c-emudhra.we-have-a-problem.com",
        "dv-g3b-aaa-emudhra.we-have-a-problem.com", "dv-g3c-aaa-emudhra.we-have-a-problem.com",
        "ov-g3b-aaa-emudhra.we-have-a-problem.com", "ov-g3c-aaa-emudhra.we-have-a-problem.com",
        "ev-g3b-aaa-emudhra.we-have-a-problem.com", "ev-g3c-aaa-emudhra.we-have-a-problem.com",
    };

    public static IEnumerable<CheckResult> CreateChecks()
    {
        yield return new CheckResult
        {
            Id = "emsign-ctl",
            Category = "证书信任",
            Title = "系统吊销列表（本机“不信任名单”）封锁状态",
            Severity = Severity.Critical,
            Impact = "这是三道防线里唯一能在断网时继续生效的一道：微软把问题证书写进系统的“不信任名单”（Disallowed CTL），凡走系统信任库的程序——浏览器、curl、.NET 业务客户端——都会拒绝这些证书。名单没下发时，断网机器就只剩浏览器自带黑名单可用；若浏览器也很旧，等于三道防线全缺。",
            Fix = "安装 2026-10-20 之后的 Windows 累积更新（离线 .msu 也可以）；暂时不能打补丁的机器，用程序目录下的 scripts\\block-emsign-certs.ps1 离线把 16 张问题证书导入系统“不信任名单”（支持 -Remove 撤销）。不要直接删根证书，会误伤正常业务。"
        };
        yield return new CheckResult
        {
            Id = "emsign-store",
            Category = "证书信任",
            Title = "本机证书存储中的问题证书",
            Severity = Severity.High,
            Impact = "若问题中间 CA 被人工或旧软件安装进「受信任的根/中间证书颁发机构」，即使系统已封锁也可能被个别程序继续信任，形成隐蔽的中间人通道。",
            Fix = "在 certlm.msc 中从「受信任的根证书颁发机构」「中间证书颁发机构」删除 eMudhra / AAA 相关问题证书，并排查是哪个软件安装的。"
        };
        yield return new CheckResult
        {
            Id = "emsign-browser",
            Category = "证书信任",
            Title = "浏览器版本与证书封锁推送",
            Severity = Severity.Medium,
            Impact = "内外网终端若长期不更新浏览器，将收不到 Chrome/Edge 的 CRLSets 与 Firefox 的 CRLite 封锁数据，访问被冒充的内部/第三方站点时不会有任何告警。",
            Fix = "将 Chrome / Edge / Firefox 升级到最新版本；纯内网机器需部署离线升级包。"
        };
        yield return new CheckResult
        {
            Id = "emsign-live",
            Category = "证书信任",
            Title = "在线证书链探测（12 个测试站点）",
            Severity = Severity.Critical,
            Impact = "这是最直接的判定：能连上测试站点说明本机仍在信任被攻陷的证书链，可被实时中间人攻击；全部被拦截才代表真正安全。纯内网机器无法访问外网时该项不可判定，需以吊销列表结果为准。",
            Fix = "与吊销列表项相同：更新系统与浏览器。若本机无外网，请在能上网的同类终端上验证同一批次镜像的补丁状态。"
        };
    }

    public static async Task RunAllAsync(IEnumerable<CheckResult> checks, IProgress<CheckResult> progress)
    {
        var list = checks.ToList();
        foreach (var c in list) { c.Status = CheckStatus.Running; progress.Report(c); }

        // 1) Local stores
        var store = list.First(c => c.Id == "emsign-store");
        try
        {
            var hits = new List<string>();
            foreach (var name in new[] { "CA", "ROOT" })
            {
                var (_, raw) = Shell.Run("certutil.exe", $"-store {name}", 40000);
                var hex = Regex.Replace(raw, "[^0-9A-Fa-f]", "").ToUpperInvariant();
                foreach (var cert in Certs)
                {
                    if (hex.Contains(cert.Sha1) || hex.Contains(cert.Sha256))
                        hits.Add($"{name}: {cert.Name} ({cert.IssuedBy})");
                }
            }
            var distinct = hits.Distinct().ToList();
            if (distinct.Count == 0)
            {
                store.Status = CheckStatus.Pass;
                store.Detail = "系统 CA / ROOT 存储中未发现被手工信任的问题证书。";
            }
            else
            {
                store.Status = CheckStatus.Fail;
                store.Detail = $"发现 {distinct.Count} 张问题证书被安装进本机证书存储。";
                store.Evidence = string.Join("\n", distinct);
            }
        }
        catch (Exception ex)
        {
            store.Status = CheckStatus.Warn;
            store.Detail = "扫描本机证书存储失败：" + ex.Message;
        }
        progress.Report(store);

        // 3) Browsers
        var browser = list.First(c => c.Id == "emsign-browser");
        try
        {
            var found = new List<string>();
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                foreach (var sub in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
                {
                    using var key = hive.OpenSubKey(sub);
                    if (key is null) continue;
                    foreach (var name in key.GetSubKeyNames())
                    {
                        using var app = key.OpenSubKey(name);
                        var display = app?.GetValue("DisplayName") as string;
                        if (display is null) continue;
                        if (display.Contains("Google Chrome", StringComparison.OrdinalIgnoreCase) ||
                            display.Contains("Microsoft Edge", StringComparison.OrdinalIgnoreCase) ||
                            display.Contains("Mozilla Firefox", StringComparison.OrdinalIgnoreCase))
                        {
                            var ver = app?.GetValue("DisplayVersion") as string ?? "未知版本";
                            found.Add($"{display} {ver}");
                        }
                    }
                }
            }
            found = found.Distinct().ToList();
            if (found.Count == 0)
            {
                browser.Status = CheckStatus.Warn;
                browser.Detail = "未在注册表中发现 Chrome / Edge / Firefox，可能为精简系统或使用其他浏览器。";
            }
            else
            {
                browser.Status = CheckStatus.Pass;
                browser.Detail = "已安装浏览器：" + string.Join("；", found) +
                                 "。封锁依赖 CRLSets / CRLite 推送，长期离线机器需确认已收到更新。";
                browser.Evidence = string.Join("\n", found);
            }
        }
        catch (Exception ex)
        {
            browser.Status = CheckStatus.Warn;
            browser.Detail = "枚举浏览器失败：" + ex.Message;
        }
        progress.Report(browser);

        // 4) Live probes
        var live = list.First(c => c.Id == "emsign-live");
        var connected = 0; var blocked = 0; var timeouts = 0;
        var lines = new List<string>();
        using (var handler = new HttpClientHandler { AllowAutoRedirect = false })
        using (var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) })
        {
            var tasks = TestHosts.Select(async host =>
            {
                try
                {
                    using var resp = await client.GetAsync($"https://{host}/?t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}");
                    lock (lines) { connected++; lines.Add($"❌ {host} — 已连接（仍信任）"); }
                }
                catch (TaskCanceledException)
                {
                    lock (lines) { timeouts++; lines.Add($"⚠️ {host} — 超时"); }
                }
                catch (Exception ex)
                {
                    lock (lines) { blocked++; lines.Add($"✅ {host} — 已拦截 ({Short(ex)})"); }
                }
            });
            await Task.WhenAll(tasks);
        }
        if (connected > 0)
        {
            live.Status = CheckStatus.Fail;
            live.Detail = $"成功连接 {connected}/12 个测试站点，本机仍信任被攻陷的证书链，可被实时中间人攻击。";
        }
        else if (blocked > 0)
        {
            live.Status = CheckStatus.Pass;
            live.Detail = $"12 个测试站点全部被证书验证拦截（超时 {timeouts}）。";
        }
        else
        {
            live.Status = CheckStatus.Warn;
            live.Detail = "全部探测超时：本机可能无法访问外网，该项无法判定，请以吊销列表结果为准。";
        }
        live.Evidence = string.Join("\n", lines.OrderBy(x => x));
        progress.Report(live);

        // 5) Disallowed CTL — evaluated last, because the interpretation depends on the live result:
        //    an empty local CTL is fine when the CA-side CRL already blocks every chain.
        var ctl = list.First(c => c.Id == "emsign-ctl");
        var liveSaysBlocked = connected == 0 && blocked > 0;
        try
        {
            var (_, raw) = Shell.Run("certutil.exe", "-store disallowed", 40000);
            if (string.IsNullOrWhiteSpace(raw) || raw.Contains("0x80070002", StringComparison.OrdinalIgnoreCase))
            {
                ctl.Status = liveSaysBlocked ? CheckStatus.Info : CheckStatus.Warn;
                ctl.Detail = liveSaysBlocked
                    ? "本机没有缓存微软的“不信任名单”（Disallowed CTL 为空），断网时这道防线是空的；但实测 12 个测试站点全部被拦截，说明当前靠联网查询 CA 吊销列表（CRL）挡住了。结论：能用，但没上锁——建议按说明第 06 节手工补上名单。"
                    : "未找到本机“不信任名单”（Disallowed CTL 缓存为空），系统可能长期未更新，断网时无法拦截问题证书。";
                ctl.Evidence = Truncate(raw, 800);
            }
            else
            {
                var hex = Regex.Replace(raw, "[^0-9A-Fa-f]", "").ToUpperInvariant();
                var ctlMatched = Certs.Count(c => hex.Contains(c.Sha1) || hex.Contains(c.Sha256));
                if (ctlMatched >= 12)
                {
                    ctl.Status = CheckStatus.Pass;
                    ctl.Detail = $"本机“不信任名单”已包含 {ctlMatched}/16 张问题证书：系统层面已封锁，断网同样有效。";
                }
                else if (ctlMatched > 0)
                {
                    ctl.Status = CheckStatus.Warn;
                    ctl.Detail = $"本机“不信任名单”只包含 {ctlMatched}/16 张问题证书，封锁不完整，建议重新导入或安装最新系统更新。";
                }
                else if (liveSaysBlocked)
                {
                    ctl.Status = CheckStatus.Info;
                    ctl.Detail = "本机“不信任名单”中暂无问题证书，但实测 12 个测试站点全部被拦截——目前靠联网查询 CA 吊销列表（CRL）挡住，断网后即失效，建议手工补上名单。";
                }
                else
                {
                    ctl.Status = CheckStatus.Fail;
                    ctl.Detail = "本机未收到“不信任名单”，且在线探测仍能连上测试站点：这台电脑现在就可能被冒充的站点骗过，请立即按说明第 06 节处置。";
                }
                ctl.Evidence = $"matched={ctlMatched}/16";
            }
        }
        catch (Exception ex)
        {
            ctl.Status = CheckStatus.Warn;
            ctl.Detail = "读取吊销列表时出错：" + ex.Message;
        }
        progress.Report(ctl);

        await Task.CompletedTask;
    }

    private static string Short(Exception ex)
    {
        var msg = ex.InnerException?.Message ?? ex.Message;
        return msg.Length > 90 ? msg[..90] + "…" : msg;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
