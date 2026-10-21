using System.Windows;
using TrustGuard.ViewModels;

namespace TrustGuard;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;

        // Support shortcut for support staff: start on the hospital-scenario tab
        if (Environment.GetCommandLineArgs().Any(a => a.Equals("--tab2", StringComparison.OrdinalIgnoreCase)))
            MainTabs.SelectedIndex = 1;

        Loaded += async (_, _) =>
        {
            if (_vm.RunAllCommand.CanExecute(null)) _vm.RunAllCommand.Execute(null);
            await Task.CompletedTask;
        };
    }
}
