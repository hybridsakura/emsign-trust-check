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

        // Support shortcut for support staff: start on the scenario tab
        if (Environment.GetCommandLineArgs().Any(a => a.Equals("--tab2", StringComparison.OrdinalIgnoreCase)))
            MainTabs.SelectedIndex = 1;

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
