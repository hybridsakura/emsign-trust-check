using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using TrustGuard.Branding;
using TrustGuard.Models;
using TrustGuard.Services;

namespace TrustGuard.ViewModels;

public sealed class CheckVerdict : INotifyPropertyChanged
{
    private string _title = "尚未检测";
    private string _subtitle = "点击「开始检测」运行本页检查项。";
    private string _glyph = "·";
    private Brush _light = Frozen("#CBD5E1");
    private Color _glow = (Color)ColorConverter.ConvertFromString("#00FFFFFF")!;

    public int PassCount { get; private set; }
    public int FailCount { get; private set; }
    public int WarnCount { get; private set; }
    public int InfoCount { get; private set; }
    public int RelevantCount { get; private set; }

    public string Title { get => _title; private set => Set(ref _title, value); }
    public string Subtitle { get => _subtitle; private set => Set(ref _subtitle, value); }
    public string Glyph { get => _glyph; private set => Set(ref _glyph, value); }
    public Brush Light { get => _light; private set => Set(ref _light, value); }
    public Color Glow { get => _glow; private set => Set(ref _glow, value); }
    public bool ShowInfo => InfoCount > 0;

    public string CountsText => $"通过 {PassCount} · 未通过 {FailCount} · 需关注 {WarnCount}" +
                                (InfoCount > 0 ? $" · 提示 {InfoCount}" : "");

    public void Update(IReadOnlyCollection<CheckResult> checks)
    {
        var relevant = checks.Where(c => c.IsRelevant).ToList();
        RelevantCount = relevant.Count;
        PassCount = relevant.Count(c => c.Status == CheckStatus.Pass);
        FailCount = relevant.Count(c => c.Status == CheckStatus.Fail);
        WarnCount = relevant.Count(c => c.Status == CheckStatus.Warn);
        InfoCount = relevant.Count(c => c.Status == CheckStatus.Info);

        if (checks.All(c => c.Status == CheckStatus.NotRun))
        {
            Title = "尚未检测";
            Subtitle = "点击「开始检测」运行本页检查项。";
            Glyph = "·";
            SetLight("#CBD5E1", "#00FFFFFF");
        }
        else if (FailCount > 0)
        {
            Title = "存在风险";
            Subtitle = $"本场景 {RelevantCount} 个检查项中有 {FailCount} 项未通过，建议立即处置。";
            Glyph = "✕";
            SetLight("#E5484D", "#00FFFFFF");
        }
        else if (WarnCount > 0)
        {
            Title = "部分项目需关注";
            Subtitle = $"未发现直接失陷项，但有 {WarnCount} 项配置偏弱，建议按处置建议加固。";
            Glyph = "!";
            SetLight("#E08700", "#00FFFFFF");
        }
        else
        {
            Title = "全部通过";
            Subtitle = $"本场景 {RelevantCount} 个检查项全部通过。";
            Glyph = "✓";
            SetLight("#16A34A", "#0016A34A");
        }
        OnPropertyChanged(nameof(CountsText));
        OnPropertyChanged(nameof(PassCount));
        OnPropertyChanged(nameof(FailCount));
        OnPropertyChanged(nameof(WarnCount));
        OnPropertyChanged(nameof(InfoCount));
        OnPropertyChanged(nameof(RelevantCount));
        OnPropertyChanged(nameof(ShowInfo));
    }

    private void SetLight(string hex, string glowHex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        b.Freeze();
        Light = b;
        Glow = (Color)ColorConverter.ConvertFromString(glowHex)!;
    }

    private static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        b.Freeze();
        return b;
    }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        OnPropertyChanged(name);
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed record ProfileOption(MachineProfile Value, string Name, string Tip);

public sealed class MainViewModel : INotifyPropertyChanged
{
    public ObservableCollection<CheckResult> EmSignChecks { get; }
    public ObservableCollection<CheckResult> ScenarioChecks { get; }
    public ICollectionView ScenarioView { get; }

    public CheckVerdict EmSignVerdict { get; } = new();
    public CheckVerdict ScenarioVerdict { get; } = new();

    private static readonly BrandConfig Brand = AppBranding.Current;

    public IReadOnlyList<ProfileOption> Profiles { get; } = new[]
    {
        new ProfileOption(MachineProfile.Intranet, Brand.ProfileNames[0], Brand.ProfileTips[0]),
        new ProfileOption(MachineProfile.InternetFacing, Brand.ProfileNames[1], Brand.ProfileTips[1]),
        new ProfileOption(MachineProfile.AirGapped, Brand.ProfileNames[2], Brand.ProfileTips[2]),
        new ProfileOption(MachineProfile.Byod, Brand.ProfileNames[3], Brand.ProfileTips[3]),
    };

    public bool IsInternal => Brand.IsInternal;
    public string FooterOrg => Brand.FooterOrg;
    public string FooterSigner => Brand.FooterSigner;
    public string FooterTech => Brand.FooterTech;

    private ProfileOption _profile;
    private bool _isRunning;
    private bool _isAdmin;
    private string _machineName = Environment.MachineName;
    private string _osText = "";
    private string _statusLine = "就绪";

    public MainViewModel()
    {
        EmSignChecks = new ObservableCollection<CheckResult>(EmSignChecker.CreateChecks());
        ScenarioChecks = new ObservableCollection<CheckResult>(EndpointChecker.CreateChecks());
        _profile = Profiles[0];

        var view = new ListCollectionView(ScenarioChecks) { GroupDescriptions = { new PropertyGroupDescription("Category") } };
        ScenarioView = view;

        foreach (var c in EmSignChecks.Concat(ScenarioChecks)) c.Profile = _profile.Value;

        IsAdmin = Elevation.IsAdministrator();
        OsText = ReadOs();

        RunAllCommand = new RelayCommand(async _ => await RunAllAsync(), _ => !IsRunning);
        ElevateCommand = new RelayCommand(_ => Elevate(), _ => !IsAdmin);
        ExportCommand = new RelayCommand(_ => Export(), _ => !IsRunning);
        OpenOfflineScriptsCommand = new RelayCommand(_ => OpenScripts());

        EmSignVerdict.Update(EmSignChecks);
        ScenarioVerdict.Update(ScenarioChecks);
    }

    public ProfileOption SelectedProfile
    {
        get => _profile;
        set
        {
            if (value is null || value == _profile) return;
            _profile = value;
            foreach (var c in EmSignChecks.Concat(ScenarioChecks)) c.Profile = value.Value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ProfileTip));
            EmSignVerdict.Update(EmSignChecks);
            ScenarioVerdict.Update(ScenarioChecks);
        }
    }

    public string ProfileTip => _profile.Tip;

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            _isRunning = value;
            OnPropertyChanged();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool IsAdmin
    {
        get => _isAdmin;
        private set
        {
            _isAdmin = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AdminText));
        }
    }

    public string AdminText => IsAdmin ? "管理员权限" : "标准权限（部分检查受限）";

    public string MachineName { get => _machineName; private set { _machineName = value; OnPropertyChanged(); } }
    public string OsText { get => _osText; private set { _osText = value; OnPropertyChanged(); } }
    public string StatusLine { get => _statusLine; private set { _statusLine = value; OnPropertyChanged(); } }

    public ICommand RunAllCommand { get; }
    public ICommand ElevateCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand OpenOfflineScriptsCommand { get; }

    private async Task RunAllAsync()
    {
        if (IsRunning) return;
        IsRunning = true;
        StatusLine = "正在检测，请稍候…";
        var sw = Stopwatch.StartNew();

        foreach (var c in EmSignChecks.Concat(ScenarioChecks))
        {
            c.Status = CheckStatus.NotRun;
            c.Detail = "";
            c.Evidence = "";
        }
        EmSignVerdict.Update(EmSignChecks);
        ScenarioVerdict.Update(ScenarioChecks);

        var progress = new Progress<CheckResult>(_ =>
        {
            EmSignVerdict.Update(EmSignChecks);
            ScenarioVerdict.Update(ScenarioChecks);
        });

        await Task.WhenAll(
            EmSignChecker.RunAllAsync(EmSignChecks, progress),
            EndpointChecker.RunAllAsync(ScenarioChecks, progress));

        EmSignVerdict.Update(EmSignChecks);
        ScenarioVerdict.Update(ScenarioChecks);
        sw.Stop();
        StatusLine = $"检测完成，用时 {sw.Elapsed.TotalSeconds:F1} 秒 · {DateTime.Now:HH:mm:ss}";
        IsRunning = false;
    }

    private void Elevate()
    {
        if (Elevation.RestartElevated())
        {
            System.Windows.Application.Current.Shutdown();
        }
        else
        {
            StatusLine = "提权被取消或失败，将继续以标准权限运行。";
        }
    }

    private void Export()
    {
        try
        {
            var path = ReportExporter.Export(this);
            StatusLine = "报告已保存：" + path;
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusLine = "导出失败：" + ex.Message;
        }
    }

    private void OpenScripts()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "scripts");
        var target = Directory.Exists(dir) ? dir : AppContext.BaseDirectory;
        try { Process.Start(new ProcessStartInfo("explorer.exe", target) { UseShellExecute = true }); } catch { }
    }

    private static string ReadOs()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var product = key?.GetValue("ProductName") as string ?? "Windows";
        var build = key?.GetValue("CurrentBuildNumber") as string ?? "";
        var ubr = key?.GetValue("UBR")?.ToString() ?? "";
        var name = product.Replace("Microsoft ", "").Replace(" Enterprise", "");
        return string.IsNullOrEmpty(build) ? name : $"{name} · {build}.{ubr}";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
