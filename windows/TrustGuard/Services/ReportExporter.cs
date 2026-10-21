using System.IO;
using System.Text;
using System.Web;
using TrustGuard.Models;
using TrustGuard.ViewModels;

namespace TrustGuard.Services;

/// <summary>Writes a self-contained HTML report next to the user (Desktop), no network needed.</summary>
public static class ReportExporter
{
    public static string Export(MainViewModel vm)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var path = Path.Combine(desktop,
            $"TrustGuard-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmmss}.html");

        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>TrustGuard 终端安全检测报告</title>
<style>
body{font-family:"Microsoft YaHei UI","Segoe UI",sans-serif;background:#f4f6fb;color:#0f172a;margin:0;padding:32px}
.wrap{max-width:980px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.meta{color:#64748b;font-size:13px;margin-bottom:22px}
h2{font-size:16px;margin:26px 0 12px}
.card{background:#fff;border:1px solid #e7ebf3;border-radius:12px;padding:16px 18px;margin-bottom:10px}
.row{display:flex;gap:12px;align-items:flex-start}
.dot{width:12px;height:12px;border-radius:50%;margin-top:5px;flex:none}
.pass{background:#22c55e}.fail{background:#ef4444}.warn{background:#f59e0b}.info{background:#94a3b8}
.title{font-weight:600;font-size:14px}
.chip{display:inline-block;font-size:11px;border-radius:8px;padding:1px 7px;margin-left:6px;vertical-align:1px}
.status{margin-left:auto;font-size:12.5px;font-weight:600;white-space:nowrap}
.detail{color:#475569;font-size:12.5px;margin:6px 0 0}
.label{color:#334155;font-size:12.5px;font-weight:600;margin-top:8px}
.text{color:#475569;font-size:12.5px;margin:2px 0 0}
pre{background:#f8fafc;border:1px solid #eef2f7;border-radius:8px;padding:8px 10px;font-size:11.5px;white-space:pre-wrap;color:#475569;margin:6px 0 0}
.footer{color:#94a3b8;font-size:12px;margin-top:26px}
</style></head><body><div class="wrap">
""");
        sb.Append($"<h1>TrustGuard 医院终端安全检测报告</h1>");
        sb.Append($"<div class=\"meta\">计算机：{HttpUtility.HtmlEncode(vm.MachineName)} · 系统：{HttpUtility.HtmlEncode(vm.OsText)} · " +
                  $"权限：{HttpUtility.HtmlEncode(vm.AdminText)} · 场景：{HttpUtility.HtmlEncode(vm.SelectedProfile.Name)} · " +
                  $"生成时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}</div>");

        AppendSection(sb, "一、emSign / eMudhra 证书信任检测", vm.EmSignChecks);
        AppendSection(sb, "二、医院业务场景风险检测", vm.HospitalChecks);

        sb.Append("<div class=\"footer\">本报告由 TrustGuard 在本地生成，未上传任何数据。证书指纹数据来源：emudhra.we-have-a-problem.com。</div>");
        sb.Append("</div></body></html>");

        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        return path;
    }

    private static void AppendSection(StringBuilder sb, string title, IEnumerable<CheckResult> checks)
    {
        sb.Append($"<h2>{HttpUtility.HtmlEncode(title)}</h2>");
        foreach (var c in checks)
        {
            var cls = c.Status switch
            {
                CheckStatus.Pass => "pass",
                CheckStatus.Fail => "fail",
                CheckStatus.Warn => "warn",
                _ => "info"
            };
            var statusColor = c.Status switch
            {
                CheckStatus.Pass => "#15803d",
                CheckStatus.Fail => "#b91c1c",
                CheckStatus.Warn => "#b45309",
                _ => "#64748b"
            };
            sb.Append("<div class=\"card\"><div class=\"row\">");
            sb.Append($"<div class=\"dot {cls}\"></div><div>");
            sb.Append($"<div class=\"title\">{HttpUtility.HtmlEncode(c.Title)}" +
                      $"<span class=\"chip\" style=\"background:{c.SeverityBackground};color:{c.SeverityBrush}\">{c.SeverityText}</span></div>");
            sb.Append($"<div class=\"detail\">{HttpUtility.HtmlEncode(c.Detail)}</div>");
            sb.Append($"<div class=\"label\">可能影响</div><div class=\"text\">{HttpUtility.HtmlEncode(c.Impact)}</div>");
            sb.Append($"<div class=\"label\">处置建议</div><div class=\"text\">{HttpUtility.HtmlEncode(c.Fix)}</div>");
            if (!string.IsNullOrWhiteSpace(c.Evidence))
                sb.Append($"<pre>{HttpUtility.HtmlEncode(c.Evidence)}</pre>");
            sb.Append("</div>");
            sb.Append($"<div class=\"status\" style=\"color:{statusColor}\">{c.StatusText}</div>");
            sb.Append("</div></div>");
        }
    }
}
