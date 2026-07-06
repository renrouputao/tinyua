using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

public class OpcUaClientTests
{

    [Fact]
    public void Constructor_Default_CreatesSuccessfully()
    {
        var client = new UaClient();
        Assert.False(client.IsConnected);
        Assert.Null(client.SessionId);
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Fact]
    public void Constructor_WithUrl_CreatesSuccessfully()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        Assert.False(client.IsConnected);
    }

    [Fact]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new UaClient((UaClientOptions)null!));
    }

    [Fact]
    public void Constructor_NullUrl_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new UaClient((string)null!));
    }

    [Fact]
    public void Constructor_WithOptions_SetsOptions()
    {
        var options = new UaClientOptions { ApplicationName = "Test", Timeout = 9999 };
        var client = new UaClient(options);
        Assert.Equal(9999u, client.Options.Timeout);
        Assert.Equal("Test", client.Options.ApplicationName);
    }

    [Fact]
    public void DefaultOptions_HaveSensibleDefaults()
    {
        var options = UaClientOptions.Default;
        Assert.True(options.Timeout > 0);
        Assert.True(options.SessionTimeout > 0);
        Assert.True(options.ChannelLifetime > 0);
        Assert.Equal(ErrorMode.Throw, options.ErrorMode);
    }

    [Fact]
    public async Task RunAsync_WithoutUrl_ThrowsInvalidOperationException()
    {
        var client = new UaClient();
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.RunAsync());
    }

    [Fact]
    public async Task RunAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await client.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.RunAsync());
    }

    [Fact]
    public async Task ReadAsync_NullNodeId_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.ReadAsync((NodeId)null!));
    }

    [Fact]
    public async Task ReadAsync_BeforeRunAsync_ThrowsOperationException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<UaOperationException>(() => client.ReadAsync(new NodeId(2258, 0)));
    }

    [Fact]
    public async Task ReadAsync_EmptyArray_ThrowsArgumentException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentException>(() => client.ReadAsync(Array.Empty<NodeId>()));
    }

    [Fact]
    public async Task WriteAsync_NullNodeId_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.WriteAsync((NodeId)null!, 42));
    }

    [Fact]
    public async Task WriteAsync_BeforeRunAsync_ThrowsOperationException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<UaOperationException>(() => client.WriteAsync(new NodeId(2258, 0), 42));
    }

    [Fact]
    public async Task WriteAsync_NullWriteValues_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.WriteAsync((WriteValue[])null!));
    }

    [Fact]
    public async Task WriteAsync_EmptyWriteValues_ThrowsArgumentException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentException>(() => client.WriteAsync(Array.Empty<WriteValue>()));
    }

    [Fact]
    public async Task BrowseAsync_NullNodeId_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.BrowseAsync((NodeId)null!));
    }

    [Fact]
    public async Task BrowseAsync_BeforeRunAsync_ThrowsOperationException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<UaOperationException>(() => client.BrowseAsync(new NodeId(84, 0)));
    }

    [Fact]
    public async Task SubscribeAsync_NullNodeId_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.SubscribeAsync((NodeId)null!, (h, v, s) => { }));
    }

    [Fact]
    public async Task SubscribeAsync_NullHandler_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.SubscribeAsync(new NodeId(2258, 0), (DataChangeHandler)null!));
    }

    [Fact]
    public async Task SubscribeAsync_EmptyNodeIdArray_ThrowsArgumentException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.SubscribeAsync(Array.Empty<NodeId>(), (h, v, s) => { }));
    }

    [Fact]
    public async Task SubscribeAsync_BeforeRunAsync_ThrowsConnectionException()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<UaConnectionException>(() =>
            client.SubscribeAsync(new NodeId(2255, 0), (h, v, s) => { }));
    }

    [Fact]
    public async Task DisposeAsync_CalledTwice_DoesNotThrow()
    {
        var client = new UaClient();
        await client.DisposeAsync();
        await client.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_CalledMultipleTimes_DoesNotThrow()
    {
        var client = new UaClient();
        for (int i = 0; i < 10; i++)
            await client.DisposeAsync();
    }

    [Fact]
    public async Task Integration_DeleteMonitoredItems_DoesNotDropConnection()
    {

        await using var probeClient = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 1000 });
        try { await probeClient.RunAsync(); }
        catch { return; }
        await probeClient.StopAsync();
        await probeClient.DisposeAsync();

        await using var client = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 5000 });
        client.StateChanged += state =>
        {
            if (state == ClientState.Reconnecting || state == ClientState.Disconnected)
                throw new InvalidOperationException(
                    $"Connection dropped after DeleteMonitoredItems! State={state}");
        };

        await client.RunAsync();
        Assert.True(client.IsConnected);

        var browseResults = await client.BrowseAsync(new NodeId(85, 0));
        Assert.NotNull(browseResults);

        var (sub, monitoredItemId) = await client.SubscribeAsync(
            new NodeId(2258, 0),
            (handle, value, status) => { },
            1000);

        Assert.True(monitoredItemId > 0, $"Expected MonitoredItemId > 0, got {monitoredItemId}");

        await Task.Delay(2000);

        var results = await client.DeleteMonitoredItemsAsync(sub, new[] { monitoredItemId });
        Assert.NotNull(results);
        Assert.True(results.Length > 0, "Expected at least one result");

        await Task.Delay(2000);

        Assert.True(client.IsConnected,
            $"Connection lost after DeleteMonitoredItems! State={client.State}");

        var browseResults2 = await client.BrowseAsync(new NodeId(85, 0));
        Assert.NotNull(browseResults2);

        await client.StopAsync();
    }

    [Fact]
    public async Task Integration_DeleteMonitoredItems_MatchesExplorerFlow()
    {

        await using var probeClient = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 1000 });
        try { await probeClient.RunAsync(); }
        catch { return; }
        await probeClient.StopAsync();
        await probeClient.DisposeAsync();

        await using var client = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 10000 });
        client.StateChanged += state =>
        {
            if (state == ClientState.Reconnecting || state == ClientState.Disconnected)
                throw new InvalidOperationException(
                    $"Connection dropped! State={state}");
        };

        await client.RunAsync();
        Assert.True(client.IsConnected);

        var rootRefs = await client.BrowseAsync(new NodeId(84, 0));
        Assert.NotNull(rootRefs);
        var objRefs = await client.BrowseAsync(new NodeId(85, 0));
        Assert.NotNull(objRefs);
        var serverRefs = await client.BrowseAsync(new NodeId(2253, 0));
        Assert.NotNull(serverRefs);

        var (sub, monitoredItemId) = await client.SubscribeAsync(
            new NodeId(2258, 0),
            (handle, value, status) => { },
            1000);

        await Task.Delay(3000);

        var results = await client.DeleteMonitoredItemsAsync(sub, new[] { monitoredItemId });

        await Task.Delay(2000);

        Assert.True(client.IsConnected,
            $"Connection lost after DeleteMonitoredItems! State={client.State}");

        var browseAfter = await client.BrowseAsync(new NodeId(85, 0));
        Assert.NotNull(browseAfter);

        await client.StopAsync();
    }

    [Fact]
    public async Task StopAsync_BeforeRunAsync_DoesNotThrow()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await client.StopAsync();
        Assert.False(client.IsConnected);
    }

    [Fact]
    public async Task ErrorMode_ReturnNull_ReturnsNullOnFailure()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions
        {
            ErrorMode = ErrorMode.ReturnNull,
            ReconnectMaxRetries = 0,
            Timeout = 500
        });
        var result = await client.ReadAsync(new NodeId(2258, 0));
        Assert.Null(result);
    }

    [Fact]
    public async Task ErrorMode_Throw_ThrowsOnFailure()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions
        {
            ErrorMode = ErrorMode.Throw,
            ReconnectMaxRetries = 0,
            Timeout = 500
        });
        await Assert.ThrowsAsync<UaOperationException>(() => client.ReadAsync(new NodeId(2258, 0)));
    }

    [Fact]
    public async Task StateChanged_FiresOnDispose()
    {
        var states = new List<ClientState>();
        var client = new UaClient("opc.tcp://localhost:4840");
        client.StateChanged += s => states.Add(s);

        await client.DisposeAsync();

        Assert.Contains(ClientState.Disconnecting, states);
        Assert.Contains(ClientState.Disconnected, states);
    }

    [Fact]
    public async Task CreateSubscription_BeforeRunAsync_ThrowsConnectionException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<UaConnectionException>(() => client.CreateSubscriptionAsync());
    }

    [Fact]
    public async Task CreateSubscriptionAsync_BeforeRunAsync_Throws()
    {
        var client = new UaClient("opc.tcp://localhost:4840", new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500 });
        await Assert.ThrowsAsync<UaConnectionException>(() => client.CreateSubscriptionAsync());
    }

    [Fact]
    public async Task DeleteSubscriptionAsync_Null_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.DeleteSubscriptionAsync(null!));
    }

    [Fact]
    public async Task DeleteMonitoredItemsAsync_Null_ThrowsArgumentNullException()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.DeleteMonitoredItemsAsync(null!, Array.Empty<uint>()));
    }

    [Fact]
    public void ParseNodeId_Integer_ReturnsNumericNodeId()
    {
        var nodeId = UaClient.ParseNodeId("i=2258");
        Assert.Equal(2258u, nodeId.GetNumericId());
    }

    [Fact]
    public void ParseNodeId_String_ReturnsStringNodeId()
    {
        var nodeId = UaClient.ParseNodeId("s=MyNode");
        Assert.Equal("MyNode", nodeId.Identifier);
    }

    [Fact]
    public void ParseNodeId_Invalid_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => UaClient.ParseNodeId(""));
    }

    [Fact]
    public void Subscription_DoubleDispose_DoesNotThrow()
    {
        var sub = new Subscription(null!, 1, 1000, 3600, 10);
        sub.Dispose();
        sub.Dispose();
    }

    [Fact]
    public void Subscription_StopPublishing_Idempotent()
    {
        var sub = new Subscription(null!, 1, 1000, 3600, 10);
        sub.StartPublishing();
        sub.StopPublishing();
        sub.StopPublishing();
    }

    [Fact]
    public void MonitoredItem_Properties_SetCorrectly()
    {
        var item = new MonitoredItem
        {
            MonitoredItemId = 42,
            ClientHandle = 7,
            NodeId = new NodeId(2258, 0),
            SamplingInterval = 500
        };
        Assert.Equal(42u, item.MonitoredItemId);
        Assert.Equal(7u, item.ClientHandle);
        Assert.Equal(2258u, item.NodeId.GetNumericId());
        Assert.Equal(500, item.SamplingInterval);
    }

    [Fact]
    public void Options_AllProperties_HaveDefaults()
    {
        var options = new UaClientOptions();
        Assert.Equal("TinyUaClient", options.ApplicationName);
        Assert.Equal(30000u, options.Timeout);
        Assert.Equal(-1, options.ReconnectMaxRetries);
        Assert.Equal(1000, options.ReconnectInitialDelayMs);
        Assert.Equal(30000, options.ReconnectMaxDelayMs);
        Assert.Equal(3600000u, options.ChannelLifetime);
        Assert.Equal(3600000d, options.SessionTimeout);
        Assert.Equal(ErrorMode.Throw, options.ErrorMode);
    }
}
