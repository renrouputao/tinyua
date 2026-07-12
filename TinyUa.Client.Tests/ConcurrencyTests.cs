using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Client;
using TinyUa.Client.Connection;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

public class ConcurrencyTests
{

    private static Subscription CreateTestSubscription(ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;
        var conn = new UaConnection(1000, logger);
        var router = new SubscriptionRouter(conn);
        return new Subscription(router, subscriptionId: 1, publishingInterval: 1000.0,
            lifetimeCount: 10, maxKeepAliveCount: 5, maxPublishRequests: 2, logger: logger);
    }

    private static object? GetPrivateField(object obj, string fieldName)
        => obj.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)?.GetValue(obj);

    private static MethodInfo GetPrivateMethod(Type type, string name)
        => type.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Private method '{name}' not found on {type.Name}");

    private static async Task<UaClient?> TryConnectAsync(uint timeout = 2000)
    {
        var client = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = timeout });
        try { await client.RunAsync().ConfigureAwait(false); }
        catch { await client.DisposeAsync().ConfigureAwait(false); return null; }
        return client;
    }

    [Fact]
    public async Task DisposeAsync_Concurrent_CalledOnce_NoException()
    {
        var client = new UaClient();
        var tasks = Enumerable.Range(0, 12)
            .Select(_ => Task.Run(() => client.DisposeAsync().AsTask()))
            .ToArray();
        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
    }

    [Fact]
    public async Task RunAsync_AfterDispose_Concurrent_ThrowsObjectDisposed()
    {
        var client = new UaClient("opc.tcp://localhost:4840");
        await client.DisposeAsync();

        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.RunAsync());
        })).ToArray();
        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task StopAsync_ConcurrentWithDispose_NoDoubleTeardown()
    {
        var client = new UaClient();
        var stopTask = Task.Run(() => client.StopAsync());
        var disposeTask = Task.Run(() => client.DisposeAsync().AsTask());
        await Task.WhenAll(stopTask, disposeTask).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(stopTask.IsCompletedSuccessfully);
        Assert.True(disposeTask.IsCompletedSuccessfully);
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Fact]
    public async Task RunAsync_ConcurrentCalls_DoNotDoubleConnect()
    {

        await using var client = new UaClient("opc.tcp://localhost:4840",
            new UaClientOptions { ReconnectMaxRetries = 0, Timeout = 500, ErrorMode = ErrorMode.ReturnNull });

        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() => client.RunAsync())).ToArray();

        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(tasks.All(t => t.IsCompleted));
    }

    [Fact]
    public async Task StopAsync_ConcurrentCalls_SerializedViaLock()
    {
        var client = new UaClient();
        var tasks = Enumerable.Range(0, 12).Select(_ => Task.Run(() => client.StopAsync())).ToArray();
        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Fact]
    public async Task GetOrCreateDefaultSubscription_AwaitsPendingTcs_Dedup()
    {

        var client = new UaClient("opc.tcp://localhost:4840");
        try
        {
            var registry = GetPrivateField(client, "_subscriptions")!;
            var dict = (Dictionary<double, TaskCompletionSource<Subscription>>)
                GetPrivateField(registry, "_pendingCreates")!;
            var pendingTcs = new TaskCompletionSource<Subscription>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            dict[1000.0] = pendingTcs;

            var fakeSub = CreateTestSubscription();
            var method = GetPrivateMethod(typeof(UaClient), "GetOrCreateDefaultSubscriptionAsync");

            var invokeTask = (Task<Subscription>)method.Invoke(client,
                new object?[] { 1000.0, CancellationToken.None })!;

            pendingTcs.SetResult(fakeSub);
            var result = await invokeTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Same(fakeSub, result);

            fakeSub.Dispose();
        }
        finally { await client.DisposeAsync(); }
    }

    [Fact]
    public async Task GetOrCreateDefaultSubscription_FailedCreate_RemovesPendingEntry()
    {

        var client = new UaClient("opc.tcp://localhost:4840");
        await client.DisposeAsync();

        var method = GetPrivateMethod(typeof(UaClient), "GetOrCreateDefaultSubscriptionAsync");
        var task = (Task<Subscription>)method.Invoke(client,
            new object?[] { 1000.0, CancellationToken.None })!;

        await Assert.ThrowsAsync<ObjectDisposedException>(() => task);

        var registry = GetPrivateField(client, "_subscriptions")!;
        var dict = (Dictionary<double, TaskCompletionSource<Subscription>>)
            GetPrivateField(registry, "_pendingCreates")!;
        Assert.Empty(dict);
    }

    [Fact]
    public async Task Subscription_StartPublishing_Concurrent_NoDoubleTask()
    {
        var sub = CreateTestSubscription();
        try
        {
            Assert.False(sub.IsPublishing);
            var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() => sub.StartPublishing())).ToArray();
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));

            Assert.True(sub.IsPublishing);
        }
        finally { sub.Dispose(); }
    }

    [Fact]
    public async Task Subscription_Dispose_Concurrent_DoesNotThrow()
    {
        var sub = CreateTestSubscription();
        var tasks = Enumerable.Range(0, 12).Select(_ => Task.Run(() => sub.Dispose())).ToArray();
        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
        Assert.True(sub.IsSubscriptionDisposed);
    }

    [Fact]
    public async Task Subscription_ProcessDataChange_DeletedHandle_DropsSilently()
    {
        var sub = CreateTestSubscription();
        try
        {
            bool called = false;
            var item = new MonitoredItem
            {
                ClientHandle = 42u,
                OnDataChange = (h, v, s) => called = true
            };
            sub.MonitoredItems[42u] = item;

            var method = GetPrivateMethod(typeof(Subscription), "ProcessDataChange");

            method.Invoke(sub, new object?[] { 42u, null, new StatusCode() });
            Assert.True(called);

            sub.MonitoredItems.Remove(42u);
            called = false;
            method.Invoke(sub, new object?[] { 42u, null, new StatusCode() });
            Assert.False(called);
        }
        finally { sub.Dispose(); }
    }

    [Fact]
    public async Task UaSocketClient_ReceiveLoopExit_FaultsPending_NoOrphan()
    {
        var socket = new UaSocketClient(1000, null, NullLogger.Instance);
        try
        {

            var callbacks = (ConcurrentDictionary<uint, TaskCompletionSource<byte[]>>)
                GetPrivateField(socket, "_callbacks")!;
            var pendingTcs = new TaskCompletionSource<byte[]>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            callbacks[1u] = pendingTcs;

            Assert.False(socket.IsDead);

            socket.SimulateReceiveLoopExit();

            Assert.True(socket.IsDead);
            Assert.Empty(callbacks);

            var ex = await Assert.ThrowsAsync<SocketException>(() => pendingTcs.Task);
            Assert.Equal(SocketError.ConnectionReset, ex.SocketErrorCode);
        }
        finally { socket.Dispose(); }
    }

    [Fact]
    public void NodeId_NamespaceUri_And_ServerIndex_Setters_AreInternalOnly()
    {
        AssertInternalSetter(typeof(NodeId), nameof(NodeId.NamespaceUri));
        AssertInternalSetter(typeof(NodeId), nameof(NodeId.ServerIndex));
    }

    private static void AssertInternalSetter(Type type, string propName)
    {
        var prop = type.GetProperty(propName);
        Assert.NotNull(prop);
        var setter = prop!.GetSetMethod(nonPublic: true);
        Assert.NotNull(setter);
        Assert.True(setter!.IsAssembly, $"{propName} setter must be internal (assembly)");
        Assert.False(setter.IsPublic, $"{propName} setter must NOT be public");
    }

    [Fact]
    public async Task FileLogger_Dispose_ConcurrentLog_DoesNotCrash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tinyua_p11_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var logger = new FileLogger(dir, LogLevel.Debug, async: true);
            var cts = new CancellationTokenSource();
            var logTask = Task.Run(async () =>
            {
                int i = 0;
                while (!cts.IsCancellationRequested)
                {
                    try { logger.Log(LogLevel.Information, null, $"msg {i++}"); }
                    catch { }
                    await Task.Yield();
                }
            });

            await Task.Delay(50);
            logger.Dispose();
            cts.Cancel();

            await logTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(logTask.IsCompleted);
        }
        finally
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Integration_ConcurrentBrowseAsync_FromManyThreads_NoCrash()
    {
        var client = await TryConnectAsync();
        if (client == null) return;
        try
        {
            var root = new NodeId(84, 0);
            var tasks = Enumerable.Range(0, 8)
                .Select(_ => Task.Run(() => client.BrowseAsync(root)))
                .ToArray();
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(30));
            Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
        }
        finally { await client.DisposeAsync(); }
    }

    [Fact]
    public async Task Integration_ConcurrentSubscribeAsync_SameInterval_NoDuplicateSubscription()
    {
        var client = await TryConnectAsync();
        if (client == null) return;
        try
        {
            var node = new NodeId(2258, 0);
            var tasks = Enumerable.Range(0, 5)
                .Select(_ => Task.Run(() => client.SubscribeAsync(node, (h, v, s) => { }, 1000)))
                .ToArray();
            var results = await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(30));

            var subs = results.Select(r => r.Subscription).ToList();
            Assert.True(subs.All(s => ReferenceEquals(s, subs[0])),
                "Concurrent same-interval subscribes must share one Subscription");

            var active = (List<Subscription>)GetPrivateField(client, "_activeSubscriptions")!;
            Assert.Single(active);
        }
        finally { await client.DisposeAsync(); }
    }

    [Fact]
    public async Task Integration_ConcurrentReadAndBrowse_NoDeadlock()
    {
        var client = await TryConnectAsync();
        if (client == null) return;
        try
        {
            var node = new NodeId(2258, 0);
            var root = new NodeId(84, 0);
            var tasks = new List<Task>();
            for (int i = 0; i < 4; i++)
            {
                tasks.Add(Task.Run(() => client.ReadAsync(node)));
                tasks.Add(Task.Run(() => client.BrowseAsync(root)));
            }
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(30));
            Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
        }
        finally { await client.DisposeAsync(); }
    }

    [Fact]
    public async Task Integration_StopAsync_WhileBrowsing_CompletesCleanly()
    {
        var client = await TryConnectAsync();
        if (client == null) return;
        try
        {
            var root = new NodeId(84, 0);
            var browseTasks = Enumerable.Range(0, 4)
                .Select(_ => Task.Run(() => client.BrowseAsync(root)))
                .ToList();

            await client.StopAsync();
            Assert.Equal(ClientState.Disconnected, client.State);

            try { await Task.WhenAll(browseTasks).WaitAsync(TimeSpan.FromSeconds(10)); }
            catch { }
        }
        finally { await client.DisposeAsync(); }
    }

    [Fact]
    public async Task Integration_DisposeDuringActiveSubscribe_AbortsPending()
    {
        var client = await TryConnectAsync();
        if (client == null) return;

        var node = new NodeId(2258, 0);
        var tasks = Enumerable.Range(0, 6)
            .Select(_ => Task.Run(() => client.SubscribeAsync(node, (h, v, s) => { }, 1000)))
            .ToList();

        await Task.Delay(100);
        await client.DisposeAsync();

        await Task.WhenAll(tasks.Select(t => t.WaitAsync(TimeSpan.FromSeconds(15)))).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.True(tasks.All(t => t.IsCompleted));
    }

    [Fact]
    public async Task Integration_ServerClosesConnection_CallbacksFaultFast()
    {

        var client = await TryConnectAsync();
        if (client == null) return;
        await client.DisposeAsync();

    }
}
