using System.Diagnostics;
using System.Security.Principal;

namespace TrustGuard.Services;

public static class Elevation
{
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Relaunches this executable elevated (UAC) and closes the current instance.</summary>
    public static bool RestartElevated()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            };
            // Preserve a self-test invocation when relaunching from automation
            var args = Environment.GetCommandLineArgs().Skip(1)
                .Where(a => a.StartsWith("--", StringComparison.Ordinal));
            foreach (var a in args) psi.ArgumentList.Add(a);

            Process.Start(psi);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
