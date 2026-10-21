using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TrustGuard.Converters;

/// <summary>Collapses an element when its bound string is empty (used for optional chips).</summary>
public sealed class EmptyToCollapsed : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
