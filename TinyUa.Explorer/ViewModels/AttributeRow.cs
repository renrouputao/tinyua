using CommunityToolkit.Mvvm.ComponentModel;
using TinyUa.Client.Subscriptions;

namespace TinyUa.Explorer.ViewModels;

public partial class AttributeRow : ObservableObject
{
    [ObservableProperty]
    private string _attribute = string.Empty;

    [ObservableProperty]
    private string _value = string.Empty;

    [ObservableProperty]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _timestamp = string.Empty;
}

public partial class SubscriptionRow : ObservableObject
{
    [ObservableProperty]
    private string _nodeId = string.Empty;

    [ObservableProperty]
    private string _displayName = string.Empty;

    [ObservableProperty]
    private string _value = string.Empty;

    [ObservableProperty]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _timestamp = string.Empty;

    [ObservableProperty]
    private int _interval = 1000;

    public Subscription? Subscription { get; set; }
    public uint MonitoredItemId { get; set; }
    public uint ClientHandle { get; set; }
}
