using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TinyUa.Core.Client;
using TinyUa.Core.Types;
using TinyUa.Core.Client.Services;
using System.Linq;
using System.Collections.Generic;

namespace TinyUa.Explorer.ViewModels;

public partial class TreeNodeViewModel : ObservableObject
{
    private readonly UaClient _client;
    private bool _childrenLoaded;
    private bool _isLoadingChildren;

    [ObservableProperty]
    private string _displayName = string.Empty;

    [ObservableProperty]
    private string _nodeIdText = string.Empty;

    [ObservableProperty]
    private string _browseName = string.Empty;

    [ObservableProperty]
    private NodeClass _nodeClass;

    [ObservableProperty]
    private bool _isExpanded;

    [ObservableProperty]
    private bool _isLoading;

    public NodeId NodeId { get; }
    public ObservableCollection<TreeNodeViewModel> Children { get; } = new();

    public bool CanHaveChildren =>
        NodeClass is NodeClass.Object or NodeClass.ObjectType
            or NodeClass.View or NodeClass.ReferenceType
            or NodeClass.DataType or NodeClass.VariableType
            or NodeClass.Variable;

    public TreeNodeViewModel(UaClient client, NodeId nodeId, string displayName, NodeClass nodeClass, string browseName)
    {
        _client = client;
        NodeId = nodeId;
        _displayName = displayName;
        _nodeClass = nodeClass;
        _browseName = browseName;
        _nodeIdText = nodeId?.ToString() ?? "";

        if (CanHaveChildren)
            Children.Add(new TreeNodeViewModel(_client, null!, "Loading...", NodeClass.Unspecified, ""));
    }

    partial void OnIsExpandedChanged(bool value)
    {
        if (value && !_childrenLoaded && CanHaveChildren)
        {
            _ = LoadChildrenAsync();
        }
    }

    public async Task LoadChildrenAsync()
    {
        if (_childrenLoaded || _isLoadingChildren || NodeId == null) return;
        _isLoadingChildren = true;

        IsLoading = true;
        try
        {
            Children.Clear();

            var seen = new HashSet<string>();
            var children = new List<TreeNodeViewModel>();

            var results = await _client.BrowseAsync(NodeId);
            if (results != null && results.Length > 0)
            {
                CollectReferences(results[0], seen, children);

                while (results[0].ContinuationPoint != null && results[0].ContinuationPoint.Length > 0)
                {
                    results = await _client.BrowseNextAsync(results[0].ContinuationPoint);
                    if (results == null || results.Length == 0) break;
                    CollectReferences(results[0], seen, children);
                }
            }

            foreach (var child in children.OrderBy(c => c.DisplayName))
                Children.Add(child);

            _childrenLoaded = true;
        }
        finally
        {
            IsLoading = false;
            _isLoadingChildren = false;
        }
    }

    private void CollectReferences(BrowseResult result,
        HashSet<string> seen, List<TreeNodeViewModel> children)
    {
        if (result.References == null) return;

        foreach (var ref_ in result.References)
        {
            var refTypeId = ref_.ReferenceTypeId?.ToString() ?? "null";
            var fwd = ref_.IsForward ? "FWD" : "INV";
            var childNodeId = ref_.NodeId ?? new NodeId();
            var childName = ref_.DisplayName?.Text ?? ref_.BrowseName?.Name ?? childNodeId.ToString();

            if (!ref_.IsForward) continue;

            var key = childNodeId.ToString();

            if (!seen.Add(key)) continue;

            var child = new TreeNodeViewModel(_client, childNodeId, childName, ref_.NodeClass,
                ref_.BrowseName?.ToString() ?? "");
            children.Add(child);
        }
    }

    public async Task RefreshAsync()
    {
        _childrenLoaded = false;
        Children.Clear();
        if (CanHaveChildren)
            Children.Add(new TreeNodeViewModel(_client, null!, "Loading...", NodeClass.Unspecified, ""));
        await LoadChildrenAsync();
    }
}
