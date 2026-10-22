using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace TrustGuard.Models;

public enum CheckStatus { NotRun, Running, Pass, Fail, Warn, Info }

public enum Severity { Critical, High, Medium, Low, Info }

/// <summary>终端场景画像。</summary>
public enum MachineProfile { Intranet, InternetFacing, AirGapped, Byod }

public sealed class CheckResult : INotifyPropertyChanged
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Category { get; init; }
    public Severity Severity { get; init; } = Severity.Medium;
    private string _detail = "";
    public string Detail
    {
        get => _detail;
        set { if (_detail == value) return; _detail = value; OnPropertyChanged(); }
    }

    public string Impact { get; init; } = "";
    public string Fix { get; init; } = "";

    private string _evidence = "";
    public string Evidence
    {
        get => _evidence;
        set { if (_evidence == value) return; _evidence = value; OnPropertyChanged(); }
    }
    public string RelevanceHint { get; init; } = "";
    public HashSet<MachineProfile> RelevantProfiles { get; init; } =
        new() { MachineProfile.Intranet, MachineProfile.InternetFacing, MachineProfile.AirGapped, MachineProfile.Byod };

    private CheckStatus _status = CheckStatus.NotRun;
    public CheckStatus Status
    {
        get => _status;
        set
        {
            if (_status == value) return;
            _status = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(StatusBrush));
            OnPropertyChanged(nameof(LightBrush));
            OnPropertyChanged(nameof(LightGlow));
            OnPropertyChanged(nameof(StatusBackground));
            OnPropertyChanged(nameof(StatusBorder));
            OnPropertyChanged(nameof(StatusGlyph));
            OnPropertyChanged(nameof(IsProblem));
            OnPropertyChanged(nameof(IsFail));
            OnPropertyChanged(nameof(ActionText));
            OnPropertyChanged(nameof(ActionBrush));
            OnPropertyChanged(nameof(ActionBackground));
            OnPropertyChanged(nameof(ActionBorder));
        }
    }

    public bool IsProblem => Status is CheckStatus.Fail or CheckStatus.Warn;

    /// <summary>Failed rows open their impact/remediation panel automatically.</summary>
    public bool IsFail => Status == CheckStatus.Fail;

    /// <summary>Flat badge fill — a tint of the status colour, no glow.</summary>
    public Brush StatusBackground => Status switch
    {
        CheckStatus.Pass => Frozen("#ECFDF3"),
        CheckStatus.Fail => Frozen("#FEF3F2"),
        CheckStatus.Warn => Frozen("#FFFAEB"),
        _ => Frozen("#F8FAFC")
    };

    public Brush StatusBorder => Status switch
    {
        CheckStatus.Pass => Frozen("#A6E9C0"),
        CheckStatus.Fail => Frozen("#F5B5AF"),
        CheckStatus.Warn => Frozen("#F2D48A"),
        _ => Frozen("#DCE3EC")
    };

    public string StatusGlyph => Status switch
    {
        CheckStatus.Pass => "✓",
        CheckStatus.Fail => "✕",
        CheckStatus.Warn => "!",
        CheckStatus.Info => "i",
        CheckStatus.Running => "…",
        _ => "·"
    };

    /// <summary>Action label shown right after the severity chip.</summary>
    public string ActionText => Status switch
    {
        CheckStatus.Pass => "无需操作",
        CheckStatus.Fail => "待解决",
        CheckStatus.Warn => "待解决",
        CheckStatus.Info => "无需操作",
        _ => ""
    };

    public Brush ActionBrush => Status switch
    {
        CheckStatus.Pass => Frozen("#15803D"),
        CheckStatus.Fail => Frozen("#B42318"),
        CheckStatus.Warn => Frozen("#B54708"),
        CheckStatus.Info => Frozen("#475569"),
        _ => Frozen("#475569")
    };

    public Brush ActionBackground => Status switch
    {
        CheckStatus.Pass => Frozen("#ECFDF3"),
        CheckStatus.Fail => Frozen("#FEF3F2"),
        CheckStatus.Warn => Frozen("#FFFAEB"),
        _ => Frozen("#F8FAFC")
    };

    public Brush ActionBorder => Status switch
    {
        CheckStatus.Pass => Frozen("#BBF7D0"),
        CheckStatus.Fail => Frozen("#FECDCA"),
        CheckStatus.Warn => Frozen("#FEDF89"),
        _ => Frozen("#E2E8F0")
    };

    public string StatusText => Status switch
    {
        CheckStatus.Pass => "通过",
        CheckStatus.Fail => "未通过",
        CheckStatus.Warn => "需关注",
        CheckStatus.Running => "检测中…",
        CheckStatus.Info => "提示",
        _ => "未检测"
    };

    public Brush StatusBrush => Status switch
    {
        CheckStatus.Pass => Frozen("#15803D"),
        CheckStatus.Fail => Frozen("#B91C1C"),
        CheckStatus.Warn => Frozen("#B45309"),
        CheckStatus.Running => Frozen("#64748B"),
        _ => Frozen("#64748B")
    };

    public Brush LightBrush => Status switch
    {
        CheckStatus.Pass => Frozen("#22C55E"),
        CheckStatus.Fail => Frozen("#EF4444"),
        CheckStatus.Warn => Frozen("#F59E0B"),
        CheckStatus.Running => Frozen("#CBD5E1"),
        _ => Frozen("#CBD5E1")
    };

    public Color LightGlow => Status switch
    {
        CheckStatus.Pass => (Color)ColorConverter.ConvertFromString("#7A22C55E")!,
        CheckStatus.Fail => (Color)ColorConverter.ConvertFromString("#7AEF4444")!,
        CheckStatus.Warn => (Color)ColorConverter.ConvertFromString("#7AF59E0B")!,
        _ => (Color)ColorConverter.ConvertFromString("#00FFFFFF")!
    };

    public string SeverityText => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高危",
        Severity.Medium => "中危",
        Severity.Low => "低危",
        _ => "信息"
    };

    public Brush SeverityBrush => Severity switch
    {
        Severity.Critical => Frozen("#B91C1C"),
        Severity.High => Frozen("#C2410C"),
        Severity.Medium => Frozen("#B45309"),
        Severity.Low => Frozen("#475569"),
        _ => Frozen("#64748B")
    };

    public Brush SeverityBackground => Severity switch
    {
        Severity.Critical => Frozen("#FEE2E2"),
        Severity.High => Frozen("#FFEDD5"),
        Severity.Medium => Frozen("#FEF3C7"),
        Severity.Low => Frozen("#F1F5F9"),
        _ => Frozen("#F1F5F9")
    };

    private MachineProfile _profile = MachineProfile.Intranet;
    public MachineProfile Profile
    {
        get => _profile;
        set
        {
            _profile = value;
            OnPropertyChanged(nameof(IsRelevant));
            OnPropertyChanged(nameof(RelevanceText));
        }
    }

    public bool IsRelevant => RelevantProfiles.Contains(_profile);

    // Only show the chip when the check is profile-specific; universal checks stay clean.
    public string RelevanceText => RelevantProfiles.Count == 4
        ? ""
        : (IsRelevant ? "本场景重点" : "其他场景适用");

    private static Brush Frozen(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        b.Freeze();
        return b;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
