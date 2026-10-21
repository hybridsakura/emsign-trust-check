using System.IO;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using TrustGuard.Models;
using TrustGuard.Services;

namespace TrustGuard;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
        {
            await RunSelfTestAsync(e.Args);
            Shutdown();
            return;
        }

        var window = new MainWindow();
        window.Show();
    }

    /// <summary>Headless run used by automation / CI: TrustGuard.exe --selftest --out report.json</summary>
    private static async Task RunSelfTestAsync(string[] args)
    {
        var outPath = Path.Combine(Path.GetTempPath(), $"trustguard-selftest-{DateTime.Now:yyyyMMdd-HHmmss}.json");
        var idx = Array.FindIndex(args, a => a.Equals("--out", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < args.Length) outPath = args[idx + 1];

        var em = EmSignChecker.CreateChecks().ToList();
        var hp = EndpointChecker.CreateChecks().ToList();
        var noop = new Progress<CheckResult>(_ => { });

        await Task.WhenAll(
            EmSignChecker.RunAllAsync(em, noop),
            EndpointChecker.RunAllAsync(hp, noop));

        string OsText()
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return $"{key?.GetValue("ProductName")} {key?.GetValue("DisplayVersion")} Build {key?.GetValue("CurrentBuildNumber")}.{key?.GetValue("UBR")}";
        }

        object Map(CheckResult c) => new
        {
            id = c.Id,
            category = c.Category,
            title = c.Title,
            severity = c.Severity.ToString(),
            status = c.Status.ToString(),
            detail = c.Detail,
            impact = c.Impact,
            fix = c.Fix,
            evidence = c.Evidence
        };

        var report = new
        {
            machine = Environment.MachineName,
            os = OsText(),
            isAdmin = Elevation.IsAdministrator(),
            timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            emSign = em.Select(Map),
            scenarios = hp.Select(Map)
        };

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        File.WriteAllText(outPath, json);
        Environment.ExitCode = hp.Any(c => c.Status == CheckStatus.Fail) || em.Any(c => c.Status == CheckStatus.Fail) ? 1 : 0;
    }
}
