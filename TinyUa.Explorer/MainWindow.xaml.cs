using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Wpf.Ui.Controls;
using TinyUa.Explorer.ViewModels;

namespace TinyUa.Explorer;

public partial class MainWindow : FluentWindow
{
    private readonly MainViewModel _viewModel = new();
    private Point _dragStartPoint;
    private TreeNodeViewModel? _dragNode;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        Closed += MainWindow_Closed;
    }

    private void TreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is TreeNodeViewModel node)
        {
            _viewModel.SelectedNode = node;
        }
    }

    private void EndpointUrl_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && _viewModel.ConnectCommand.CanExecute(null))
        {
            _viewModel.ConnectCommand.Execute(null);
        }
    }

    private void TreeView_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        _dragStartPoint = e.GetPosition(null);
        _dragNode = FindTreeViewItemDataContext(e.OriginalSource);
    }

    private void TreeView_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (_dragNode == null || e.LeftButton != MouseButtonState.Pressed)
            return;

        var pos = e.GetPosition(null);
        var diff = _dragStartPoint - pos;
        if (Math.Abs(diff.X) < SystemParameters.MinimumHorizontalDragDistance ||
            Math.Abs(diff.Y) < SystemParameters.MinimumVerticalDragDistance)
            return;

        var data = new DataObject(typeof(TreeNodeViewModel), _dragNode);
        DragDrop.DoDragDrop((DependencyObject)sender, data, DragDropEffects.Copy);
        _dragNode = null;
    }

    private static TreeNodeViewModel? FindTreeViewItemDataContext(object source)
    {
        if (source is DependencyObject d)
        {

            while (d != null)
            {
                if (d is System.Windows.Controls.TreeViewItem item && item.DataContext is TreeNodeViewModel vm)
                    return vm;
                d = VisualTreeHelper.GetParent(d);
            }
        }
        return null;
    }

    private void MonitoredItems_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(typeof(TreeNodeViewModel)))
            e.Effects = DragDropEffects.Copy;
        else
            e.Effects = DragDropEffects.None;
        e.Handled = true;
    }

    private void MonitoredItems_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(typeof(TreeNodeViewModel)) is TreeNodeViewModel node)
        {
            _viewModel.SubscribeToNodeCommand.Execute(node);
        }
        e.Handled = true;
    }

    private void CopyAttributeValue_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.MenuItem mi && mi.Parent is ContextMenu cm && cm.PlacementTarget is System.Windows.Controls.DataGrid grid)
        {
            var value = GetSelectedCellValue(grid);
            if (!string.IsNullOrEmpty(value))
                Clipboard.SetText(value);
        }
    }

    private static string? GetSelectedCellValue(System.Windows.Controls.DataGrid grid)
    {
        if (grid.SelectedCells.Count == 0) return null;
        var cellInfo = grid.SelectedCells[0];
        if (cellInfo.Column is DataGridTextColumn col && cellInfo.Item is AttributeRow row)
        {
            var binding = col.Binding as System.Windows.Data.Binding;
            if (binding?.Path?.Path == "Value") return row.Value;
            if (binding?.Path?.Path == "Attribute") return row.Attribute;
            if (binding?.Path?.Path == "Status") return row.Status;
            if (binding?.Path?.Path == "Timestamp") return row.Timestamp;
        }
        return null;
    }

    private void MonitoredItemsGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {

        var dep = (DependencyObject)e.OriginalSource;
        while (dep != null && dep is not System.Windows.Controls.DataGridRow)
            dep = VisualTreeHelper.GetParent(dep);
        if (dep is System.Windows.Controls.DataGridRow row)
            row.IsSelected = true;
    }

    private void ChangeInterval_Click(object sender, RoutedEventArgs e)
    {
        if (MonitoredItemsGrid.SelectedItem is not SubscriptionRow row) return;
        var input = ShowInputDialog("Change Interval", $"Enter new publishing interval (ms) for '{row.DisplayName}':", row.Interval.ToString());
        if (input == null) return;
        if (!int.TryParse(input, out var interval) || interval < 50 || interval > 60000)
        {
            _viewModel.StatusText = "Invalid interval (50-60000 ms)";
            return;
        }

        row.Interval = interval;
        _viewModel.ChangeIntervalCommand.Execute(row);
    }

    private void Unsubscribe_Click(object sender, RoutedEventArgs e)
    {
        if (MonitoredItemsGrid.SelectedItem is not SubscriptionRow row) return;
        _viewModel.UnsubscribeCommand.Execute(row);
    }

    private static string? ShowInputDialog(string title, string prompt, string defaultValue)
    {
        var window = new Window
        {
            Title = title,
            Width = 360,
            Height = 180,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Owner = Application.Current.MainWindow
        };

        var stack = new StackPanel { Margin = new Thickness(16) };
        var label = new System.Windows.Controls.TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
        var textBox = new System.Windows.Controls.TextBox { Text = defaultValue, Padding = new Thickness(6, 4, 6, 4) };
        textBox.SelectAll();
        textBox.Focus();
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        var okBtn = new System.Windows.Controls.Button { Content = "OK", Padding = new Thickness(20, 4, 20, 4), Margin = new Thickness(4, 0, 0, 0), IsDefault = true };
        var cancelBtn = new System.Windows.Controls.Button { Content = "Cancel", Padding = new Thickness(20, 4, 20, 4), Margin = new Thickness(4, 0, 0, 0), IsCancel = true };
        btnPanel.Children.Add(okBtn);
        btnPanel.Children.Add(cancelBtn);
        stack.Children.Add(label);
        stack.Children.Add(textBox);
        stack.Children.Add(btnPanel);
        window.Content = stack;

        okBtn.Click += (_, _) => { window.DialogResult = true; window.Close(); };

        return window.ShowDialog() == true ? textBox.Text : null;
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        _viewModel.Dispose();
    }
}
