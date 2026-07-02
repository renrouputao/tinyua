using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TinyUa.Core.Client;
using TinyUa.Core.Client.Services;
using TinyUa.Core.Client.Subscriptions;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using TinyUa.Explorer.Services;
using TinyUa.Explorer.Views;

namespace TinyUa.Explorer.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private UaClient? _client;
    private readonly SynchronizationContext _syncContext;
    private CancellationTokenSource? _connectCts;
    private readonly SecuritySettingsStore _securityStore = new();
    private StoredSecuritySettings? _currentSecurity;

    private static readonly string HistoryFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "TinyUa.Explorer", "endpoint_history.json");

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(SecurityCommand))]
    private string _endpointUrl = "opc.tcp://localhost:4840";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    [NotifyPropertyChangedFor(nameof(CanEditEndpoint))]
    private bool _isConnecting;

    public bool CanEditEndpoint => !IsConnected && !IsConnecting;

    [ObservableProperty]
    private string _connectionStatus = "Disconnected";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEditEndpoint))]
    [NotifyCanExecuteChangedFor(nameof(SecurityCommand))]
    private bool _isConnected;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private string _sessionInfo = "";

    [ObservableProperty]
    private TreeNodeViewModel? _selectedNode;

    [ObservableProperty]
    private string _writeValue = "";

    [ObservableProperty]
    private string _securitySummary = "None / Anonymous (default)";

    public ObservableCollection<TreeNodeViewModel> RootNodes { get; } = new();
    public ObservableCollection<AttributeRow> Attributes { get; } = new();
    public ObservableCollection<SubscriptionRow> Subscriptions { get; } = new();
    public ObservableCollection<string> EndpointHistory { get; } = new();

    public MainViewModel()
    {
        _syncContext = SynchronizationContext.Current ?? new SynchronizationContext();
        LoadEndpointHistory();
        ApplySavedSecurityIfAny();
    }

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task ConnectAsync()
    {
        try
        {
            IsConnecting = true;
            StatusText = "Connecting...";
            _connectCts = new CancellationTokenSource();
            var options = new UaClientOptions
            {
                ReconnectMaxRetries = 3,
                ReconnectInitialDelayMs = 500
            };
            if (_currentSecurity != null)
            {
                options.Security = BuildSecurityOptions(_currentSecurity);
            }
            _client = new UaClient(EndpointUrl, options);
            _client.StateChanged += OnClientStateChanged;
            await _client.RunAsync(_connectCts.Token);

            IsConnected = true;
            ConnectionStatus = "Connected";
            StatusText = "Connected — browsing root...";
            SessionInfo = $"Session: {_client.SessionId}";

            AddToEndpointHistory(EndpointUrl);
            await LoadRootNodesAsync();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Connection cancelled";
        }
        catch (Exception ex)
        {
            StatusText = $"Connect failed: {ex.Message}";
            MessageBox.Show($"Failed to connect:\n{ex.Message}", "Connection Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsConnecting = false;
            _connectCts?.Dispose();
            _connectCts = null;
        }
    }

    private bool CanConnect() => !IsConnected && !IsConnecting && !string.IsNullOrWhiteSpace(EndpointUrl);

    [RelayCommand(CanExecute = nameof(CanEditSecurity))]
    private void Security()
    {
        var result = SecuritySelectionDialog.Show(EndpointUrl, _securityStore.Load(EndpointUrl), Application.Current.MainWindow);
        if (result == null) return;

        _currentSecurity = new StoredSecuritySettings
        {
            Policy = result.Policy,
            Mode = result.Mode,
            TokenType = result.TokenType,
            Username = result.Username,
            EncryptedPasswordBase64 = SecuritySettingsStore.EncryptPassword(result.Password),
            PlainPassword = result.Password
        };
        _securityStore.Save(EndpointUrl, _currentSecurity);
        RefreshSecuritySummary();
    }

    private bool CanEditSecurity() => CanEditEndpoint && !string.IsNullOrWhiteSpace(EndpointUrl);

    private static SecurityOptions BuildSecurityOptions(StoredSecuritySettings s) => new()
    {
        Policy = s.Policy,
        Mode = s.Mode,
        UserIdentity = new UserIdentityOptions
        {
            Type = s.TokenType,
            Username = s.Username,
            Password = s.PlainPassword
        }
    };

    private void ApplySavedSecurityIfAny()
    {
        _currentSecurity = _securityStore.Load(EndpointUrl);
        RefreshSecuritySummary();
    }

    private void RefreshSecuritySummary()
    {
        if (_currentSecurity == null)
        {
            SecuritySummary = "None / Anonymous (default)";
            return;
        }
        var user = _currentSecurity.TokenType == UserTokenType.UserName && !string.IsNullOrEmpty(_currentSecurity.Username)
            ? $"{_currentSecurity.TokenType}({_currentSecurity.Username})"
            : _currentSecurity.TokenType.ToString();
        SecuritySummary = $"{_currentSecurity.Policy} / {_currentSecurity.Mode} · {user}";
    }

    partial void OnEndpointUrlChanged(string value)
    {
        ApplySavedSecurityIfAny();
    }

    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task DisconnectAsync()
    {
        if (_client == null) return;

        try
        {
            StatusText = "Disconnecting...";

            if (IsConnecting && _connectCts != null)
            {
                _connectCts.Cancel();
                await Task.Delay(500);
            }

            if (IsConnected)
            {
                var stopTask = _client.StopAsync();
                var timeoutTask = Task.Delay(5000);
                if (await Task.WhenAny(stopTask, timeoutTask) == timeoutTask)
                    StatusText = "Disconnect timed out — forcing close";
            }
        }
        catch { }

        try { await _client.DisposeAsync(); } catch { }

        IsConnected = false;
        IsConnecting = false;
        ConnectionStatus = "Disconnected";
        StatusText = "Disconnected";
        SessionInfo = "";
        RootNodes.Clear();
        Attributes.Clear();
        Subscriptions.Clear();
        _client = null;
    }

    private bool CanDisconnect() => IsConnected || IsConnecting;

    private void OnClientStateChanged(ClientState state)
    {
        _syncContext.Post(_ =>
        {
            if (state == ClientState.Connected)
            {
                IsConnected = true;
                ConnectionStatus = "Connected";
            }
            else if (state == ClientState.Reconnecting)
            {
                ConnectionStatus = "Reconnecting...";
                StatusText = "Connection lost — reconnecting...";
            }
            else if (state == ClientState.Disconnected)
            {
                IsConnected = false;
                ConnectionStatus = "Disconnected";
            }
        }, null);
    }

    private async Task LoadRootNodesAsync()
    {
        RootNodes.Clear();

        var objectsNode = new TreeNodeViewModel(_client!, new NodeId(85), "Objects", NodeClass.Object, "0:Objects");
        var typesNode = new TreeNodeViewModel(_client!, new NodeId(86), "Types", NodeClass.Object, "0:Types");
        var viewsNode = new TreeNodeViewModel(_client!, new NodeId(87), "Views", NodeClass.Object, "0:Views");
        RootNodes.Add(objectsNode);
        RootNodes.Add(typesNode);
        RootNodes.Add(viewsNode);

        objectsNode.IsExpanded = true;
        StatusText = "Ready";
    }

    [RelayCommand]
    private async Task RefreshNodeAsync()
    {
        if (SelectedNode == null) return;
        StatusText = $"Refreshing {SelectedNode.DisplayName}...";
        await SelectedNode.RefreshAsync();
        StatusText = "Ready";
    }

    partial void OnSelectedNodeChanged(TreeNodeViewModel? value)
    {
        _ = LoadAttributesAsync(value);
    }

    private async Task LoadAttributesAsync(TreeNodeViewModel? node)
    {
        Attributes.Clear();
        if (node?.NodeId == null || _client == null) return;

        try
        {

            var attrs = new[]
            {
                (AttributeId.NodeId, "NodeId"),
                (AttributeId.NodeClass, "NodeClass"),
                (AttributeId.BrowseName, "BrowseName"),
                (AttributeId.DisplayName, "DisplayName"),
                (AttributeId.Description, "Description"),
                (AttributeId.Value, "Value"),
                (AttributeId.DataType, "DataType"),
                (AttributeId.AccessLevel, "AccessLevel"),
            };

            foreach (var (attrId, label) in attrs)
            {
                try
                {
                    var dv = await _client.ReadAsync(node.NodeId, attrId);
                    if (dv != null)
                    {
                        Attributes.Add(new AttributeRow
                        {
                            Attribute = label,
                            Value = FormatAttributeValue(attrId, dv.Value?.Value),
                            Status = dv.StatusCode?.IsGood == true ? "Good" : dv.StatusCode?.Value.ToString("X8") ?? "",
                            Timestamp = dv.SourceTimestamp?.ToString("HH:mm:ss.fff") ?? ""
                        });
                    }
                }
                catch
                {

                }
            }
        }
        catch (Exception ex)
        {
            StatusText = $"Read failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ReadValueAsync()
    {
        if (SelectedNode?.NodeId == null || _client == null) return;

        try
        {
            var dv = await _client.ReadAsync(SelectedNode.NodeId, AttributeId.Value);
            if (dv != null)
            {
                WriteValue = dv.Value?.Value?.ToString() ?? "";
                StatusText = $"Read: {WriteValue} [{dv.StatusCode}]";
            }
        }
        catch (Exception ex)
        {
            StatusText = $"Read failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task WriteValueAsync()
    {
        if (SelectedNode?.NodeId == null || _client == null) return;

        try
        {
            var (parsedValue, variantType) = await ParseWriteValueAsync(SelectedNode.NodeId, WriteValue);
            await _client.WriteAsync(SelectedNode.NodeId, parsedValue);
            StatusText = $"Written: {WriteValue} ({variantType})";
            await LoadAttributesAsync(SelectedNode);
        }
        catch (Exception ex)
        {
            StatusText = $"Write failed: {ex.Message}";
        }
    }

    private async Task<(object value, VariantType variantType)> ParseWriteValueAsync(NodeId nodeId, string text)
    {
        var variantType = await ResolveVariantTypeAsync(nodeId);
        object value = variantType switch
        {
            VariantType.Boolean => bool.TryParse(text, out var b) ? b : text.Equals("1", StringComparison.OrdinalIgnoreCase),
            VariantType.SByte => sbyte.Parse(text),
            VariantType.Byte => byte.Parse(text),
            VariantType.Int16 => short.Parse(text),
            VariantType.UInt16 => ushort.Parse(text),
            VariantType.Int32 => int.Parse(text),
            VariantType.UInt32 => uint.Parse(text),
            VariantType.Int64 => long.Parse(text),
            VariantType.UInt64 => ulong.Parse(text),
            VariantType.Float => float.Parse(text),
            VariantType.Double => double.Parse(text),
            VariantType.String => text,
            VariantType.DateTime => DateTime.Parse(text),
            _ => text
        };
        return (value, variantType);
    }

    private async Task<VariantType> ResolveVariantTypeAsync(NodeId nodeId)
    {
        try
        {
            var dv = await _client!.ReadAsync(nodeId, AttributeId.DataType);
            if (dv?.Value?.Value is not NodeId dtNodeId)
                return VariantType.String;

            if (dtNodeId.NamespaceIndex != 0)
                return VariantType.String;

            uint id = dtNodeId.NodeIdType switch
            {
                NodeIdType.TwoByte => (byte)dtNodeId.Identifier!,
                NodeIdType.FourByte => (ushort)dtNodeId.Identifier!,
                NodeIdType.Numeric => (uint)dtNodeId.Identifier!,
                _ => 0
            };

            return id switch
            {
                1  => VariantType.Boolean,
                2  => VariantType.SByte,
                3  => VariantType.Byte,
                4  => VariantType.Int16,
                5  => VariantType.UInt16,
                6  => VariantType.Int32,
                7  => VariantType.UInt32,
                8  => VariantType.Int64,
                9  => VariantType.UInt64,
                10 => VariantType.Float,
                11 => VariantType.Double,
                12 => VariantType.String,
                13 => VariantType.DateTime,
                14 => VariantType.Guid,
                15 => VariantType.ByteString,
                _  => VariantType.String
            };
        }
        catch
        {
            return VariantType.String;
        }
    }

    [RelayCommand]
    private async Task SubscribeAsync()
    {
        if (SelectedNode?.NodeId == null || _client == null) return;
        await SubscribeToNodeAsync(SelectedNode);
    }

    [RelayCommand]
    private async Task SubscribeToNodeAsync(TreeNodeViewModel node)
    {
        if (node?.NodeId == null || _client == null) return;

        try
        {
            var nodeIdStr = node.NodeId.ToString();
            var displayName = node.DisplayName;

            if (FindSubscriptionRow(nodeIdStr) != null)
            {
                StatusText = $"Already subscribed to {displayName}";
                return;
            }

            var row = new SubscriptionRow
            {
                NodeId = nodeIdStr,
                DisplayName = displayName,
                Value = "—",
                Status = "Pending",
                Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
                Interval = 1000
            };
            Subscriptions.Add(row);

            var nodeId = node.NodeId;
            var (sub, monitoredItemId) = await _client.SubscribeAsync(
                nodeId,
                (clientHandle, value, status) =>
                {
                    _syncContext.Post(_ =>
                    {
                        row.Value = value?.ToString() ?? "null";
                        row.Timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                        row.Status = status.IsGood ? "Good" : status.ToString();
                    }, null);
                },
                1000);

            row.Subscription = sub;
            row.MonitoredItemId = monitoredItemId;

            StatusText = $"Subscribed to {displayName}";
        }
        catch (Exception ex)
        {
            StatusText = $"Subscribe failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ChangeIntervalAsync(SubscriptionRow row)
    {
        if (row?.Subscription == null || _client == null) return;

        var newInterval = row.Interval;
        if (newInterval < 50 || newInterval > 60000) return;

        try
        {

            await _client.DeleteMonitoredItemsAsync(row.Subscription, new[] { row.MonitoredItemId });

            var nodeId = NodeId.Parse(row.NodeId);
            var (sub, monitoredItemId) = await _client.SubscribeAsync(
                nodeId,
                (clientHandle, value, status) =>
                {
                    _syncContext.Post(_ =>
                    {
                        row.Value = value?.ToString() ?? "null";
                        row.Timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                        row.Status = status.IsGood ? "Good" : status.ToString();
                    }, null);
                },
                newInterval);

            row.Subscription = sub;
            row.MonitoredItemId = monitoredItemId;
            row.Interval = newInterval;
            row.Status = "Pending";
            StatusText = $"Interval changed to {newInterval}ms for {row.DisplayName}";
        }
        catch (Exception ex)
        {
            StatusText = $"Change interval failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task UnsubscribeAsync(SubscriptionRow row)
    {
        if (row?.Subscription == null || _client == null) return;
        try
        {
            var results = await _client.DeleteMonitoredItemsAsync(row.Subscription, new[] { row.MonitoredItemId });
            var badResults = results?.Where(r => !r.IsGood).ToList();
            if (badResults != null && badResults.Count > 0)
                StatusText = $"Unsubscribe partial: {string.Join(", ", badResults.Select(r => r.ToString()))} (ItemId={row.MonitoredItemId})";
            else
            {
                Subscriptions.Remove(row);
                StatusText = $"Unsubscribed from {row.DisplayName}";
            }
        }
        catch (Exception ex)
        {
            StatusText = $"Unsubscribe failed: {ex.Message} (ItemId={row.MonitoredItemId})";
        }
    }

    [RelayCommand]
    private void CopyNodeId()
    {
        if (SelectedNode?.NodeId == null) return;
        var nodeIdStr = SelectedNode.NodeId.ToString();
        if (!string.IsNullOrEmpty(nodeIdStr))
        {
            Clipboard.SetText(nodeIdStr);
            StatusText = $"Copied NodeId: {nodeIdStr}";
        }
    }

    private SubscriptionRow? FindSubscriptionRow(string nodeId)
    {
        foreach (var row in Subscriptions)
        {
            if (row.NodeId == nodeId) return row;
        }
        return null;
    }

    private static string FormatAttributeValue(AttributeId attrId, object? rawValue)
    {
        if (rawValue == null) return "";
        return attrId switch
        {
            AttributeId.DataType => FormatDataType(rawValue),
            AttributeId.AccessLevel => FormatAccessLevel(rawValue),
            AttributeId.NodeClass => FormatNodeClass(rawValue),
            _ => rawValue.ToString() ?? ""
        };
    }

    private static string FormatDataType(object rawValue)
    {
        if (rawValue is NodeId dtNodeId)
        {
            var typeName = GetBuiltInTypeName(dtNodeId);
            return typeName != null ? $"{typeName} ({dtNodeId})" : dtNodeId.ToString() ?? "";
        }
        return rawValue.ToString() ?? "";
    }

    private static string? GetBuiltInTypeName(NodeId nodeId)
    {
        if (nodeId.NamespaceIndex != 0) return null;
        uint id = nodeId.NodeIdType switch
        {
            NodeIdType.TwoByte => (byte)nodeId.Identifier!,
            NodeIdType.FourByte => (ushort)nodeId.Identifier!,
            NodeIdType.Numeric => (uint)nodeId.Identifier!,
            _ => 0
        };
        return id switch
        {
            1 => "Boolean", 2 => "SByte", 3 => "Byte", 4 => "Int16", 5 => "UInt16",
            6 => "Int32", 7 => "UInt32", 8 => "Int64", 9 => "UInt64",
            10 => "Float", 11 => "Double", 12 => "String", 13 => "DateTime",
            14 => "Guid", 15 => "ByteString", 16 => "XmlElement",
            17 => "NodeId", 18 => "ExpandedNodeId", 19 => "StatusCode",
            20 => "QualifiedName", 21 => "LocalizedText", 22 => "ExtensionObject",
            23 => "DataValue", 24 => "Variant", 25 => "DiagnosticInfo",
            _ => null
        };
    }

    private static string FormatAccessLevel(object rawValue)
    {
        byte val = rawValue switch
        {
            byte b => b,
            uint u => (byte)u,
            int i => (byte)i,
            _ => (byte)0
        };
        var flags = new List<string>();
        if ((val & 0x01) != 0) flags.Add("CurrentRead");
        if ((val & 0x02) != 0) flags.Add("CurrentWrite");
        if ((val & 0x04) != 0) flags.Add("HistoryRead");
        if ((val & 0x08) != 0) flags.Add("HistoryWrite");
        if ((val & 0x10) != 0) flags.Add("SemanticChange");
        return flags.Count > 0 ? $"{string.Join(" | ", flags)} ({val})" : val.ToString();
    }

    private static string FormatNodeClass(object rawValue)
    {
        int val = rawValue switch
        {
            int i => i,
            uint u => (int)u,
            byte b => b,
            _ => 0
        };
        return Enum.IsDefined(typeof(NodeClass), val)
            ? $"{(NodeClass)val} ({val})"
            : val.ToString();
    }

    private void LoadEndpointHistory()
    {
        try
        {
            if (File.Exists(HistoryFilePath))
            {
                var json = File.ReadAllText(HistoryFilePath);
                var urls = JsonSerializer.Deserialize<List<string>>(json);
                if (urls != null)
                    foreach (var url in urls)
                        EndpointHistory.Add(url);
            }
        }
        catch { }
    }

    private void AddToEndpointHistory(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        EndpointHistory.Remove(url);
        EndpointHistory.Insert(0, url);
        if (EndpointHistory.Count > 20)
            EndpointHistory.RemoveAt(EndpointHistory.Count - 1);
        SaveEndpointHistory();
    }

    private void SaveEndpointHistory()
    {
        try
        {
            var dir = Path.GetDirectoryName(HistoryFilePath);
            if (dir != null) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(EndpointHistory.ToList());
            File.WriteAllText(HistoryFilePath, json);
        }
        catch { }
    }

    public void Dispose()
    {
        if (_client != null)
        {
            try { _client.DisposeAsync().AsTask().Wait(2000); } catch { }
        }
    }
}
