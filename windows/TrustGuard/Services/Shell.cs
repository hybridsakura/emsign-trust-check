using System.Diagnostics;
using System.IO;
using System.Text;

namespace TrustGuard.Services;

/// <summary>Process helpers. Everything runs locally; no network is required by these calls.</summary>
public static class Shell
{
    public static (int Code, string Output) Run(string exe, string args, int timeoutMs = 20000)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p is null) return (-1, "");
            var sb = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return (-2, sb + "\n[timeout]");
            }
            return (p.ExitCode, sb.ToString());
        }
        catch (Exception ex)
        {
            return (-3, ex.Message);
        }
    }

    /// <summary>Runs an inline PowerShell script (written to a temp file to avoid quoting issues).</summary>
    public static string PowerShell(string script, int timeoutMs = 25000)
    {
        var path = Path.Combine(Path.GetTempPath(), "tg_" + Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            var header = "$ErrorActionPreference='Continue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[Console]::OutputEncoding;\n";
            File.WriteAllText(path, "\uFEFF" + header + script, new UTF8Encoding(false));
            var (_, output) = Run("powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{path}\"", timeoutMs);
            return output.Trim();
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    public static bool TryParseBool(string text, out bool value)
    {
        value = false;
        var t = text.Trim().TrimEnd('\r', '\n');
        if (t.Equals("True", StringComparison.OrdinalIgnoreCase)) { value = true; return true; }
        if (t.Equals("False", StringComparison.OrdinalIgnoreCase)) { value = false; return true; }
        return false;
    }
}
