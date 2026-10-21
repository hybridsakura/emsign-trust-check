namespace TrustGuard.Branding;

/// <summary>All user-facing strings that differ between the public and internal builds.</summary>
public sealed record BrandConfig(
    bool IsInternal,
    string WindowTitle,
    string HeaderSuffix,
    string Subtitle,
    string TabScenario,
    string ReportTitle,
    string[] ProfileNames,
    string[] ProfileTips,
    string FooterOrg,
    string FooterSigner,
    string FooterTech);

public static class AppBranding
{
#if INTERNAL
    public static BrandConfig Current => InternalBranding.Value;
#else
    public static BrandConfig Current => Public;
#endif

#if !INTERNAL
    private static readonly BrandConfig Public = new(
        IsInternal: false,
        WindowTitle: "TrustGuard · 终端安全检测",
        HeaderSuffix: "终端安全检测",
        Subtitle: "本地运行 · 不收集上传任何数据",
        TabScenario: "终端场景风险",
        ReportTitle: "TrustGuard 终端安全检测报告",
        ProfileNames: new[] { "内网终端", "外网终端", "断网终端", "自带设备（接入内网）" },
        ProfileTips: new[]
        {
            "无法访问互联网的内网办公/业务终端：重点是横向移动、共享与 U 盘摆渡。",
            "可访问互联网的终端：重点是钓鱼、浏览器漏洞与外部扫描入口。",
            "仅靠 U 盘交换数据的隔离终端：重点是介质管控、自动播放与离线补丁。",
            "个人设备接入内网：重点是纳管状态、磁盘加密与未授权远控。"
        },
        FooterOrg: "",
        FooterSigner: "",
        FooterTech: "");
#endif
}
