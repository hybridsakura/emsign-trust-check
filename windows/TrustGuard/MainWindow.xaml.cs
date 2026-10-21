using System.Windows;
using TrustGuard.Branding;
using TrustGuard.ViewModels;

namespace TrustGuard;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        ApplyBranding();

        // Support shortcuts for support staff
        var args = Environment.GetCommandLineArgs();
        if (args.Any(a => a.Equals("--tab2", StringComparison.OrdinalIgnoreCase)))
            MainTabs.SelectedIndex = 1;

        ExplainToggle.Checked += (_, _) =>
        {
            ExplainPanel.Visibility = Visibility.Visible;
            ExplainToggle.Content = "📘 收起说明";
        };
        ExplainToggle.Unchecked += (_, _) =>
        {
            ExplainPanel.Visibility = Visibility.Collapsed;
            ExplainToggle.Content = "📘 这个证书漏洞是怎么回事？（点开看通俗说明）";
        };
        if (args.Any(a => a.Equals("--explain", StringComparison.OrdinalIgnoreCase)))
            ExplainToggle.IsChecked = true;

        Loaded += async (_, _) =>
        {
            if (_vm.RunAllCommand.CanExecute(null)) _vm.RunAllCommand.Execute(null);
            await Task.CompletedTask;
        };
    }

    private void ApplyBranding()
    {
        var brand = AppBranding.Current;
        Title = brand.WindowTitle;
        HeaderSuffix.Text = "  " + brand.HeaderSuffix;
        ScenarioTab.Header = brand.TabScenario;

        if (!brand.IsInternal) return;
        BrandFooter.Visibility = Visibility.Visible;
        FooterOrgText.Text = brand.FooterOrg;
        FooterSignerText.Text = "署名：" + brand.FooterSigner;
        FooterTechText.Text = brand.FooterTech;
    }
}
