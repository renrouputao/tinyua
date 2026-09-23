using System.Net;
using System.Net.Sockets;
using TinyUa.Client.Discovery;
using TinyUa.Core.Logging;
using TinyUa.Testing;

namespace TinyUa.Client.Tests;

public class ConnectionCancellationTests
{
    [Theory]
    [InlineData(1, 0, ErrorMode.Throw)]
    [InlineData(1, 4, ErrorMode.Throw)]
    [InlineData(1, 12, ErrorMode.Throw)]
    [InlineData(2, 0, ErrorMode.Throw)]
    [InlineData(1, 0, ErrorMode.ReturnNull)]
    public async Task RunAsync_CancelDuringHandshake_ThrowsAndAllowsAnotherAttempt(
        int response, int prefix, ErrorMode errorMode)
    {
        await using var server = new UaFaultProxy(stallResponse: response, forwardPrefixBytes: prefix);
        await using var client = new UaClient(server.Url, new UaClientOptions
        {
            Timeout = 10000, ReconnectMaxRetries = 0, ErrorMode = errorMode
        });
        using var cancellation = new CancellationTokenSource();
        var run = client.RunAsync(cancellation.Token);
        await server.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(3));
        cancellation.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Equal(ClientState.Disconnected, client.State);
        Assert.Null(client.SessionId);

        using var secondCancellation = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.RunAsync(secondCancellation.Token).WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(2, server.Accepted);
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Theory]
    [InlineData(ErrorMode.Throw)]
    [InlineData(ErrorMode.ReturnNull)]
    public async Task RunAsync_CancelDuringRetryDelay_ThrowsAndResetsState(ErrorMode errorMode)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var retrying = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var logger = new DelegateLogger((_, _, message) =>
        {
            if (message.Contains("retrying in")) retrying.TrySetResult(true);
        });
        await using var client = new UaClient($"opc.tcp://127.0.0.1:{port}", new UaClientOptions
        {
            ReconnectInitialDelayMs = 10000, ReconnectMaxDelayMs = 10000, ErrorMode = errorMode
        }, logger);
        using var cancellation = new CancellationTokenSource();
        var run = client.RunAsync(cancellation.Token);
        await retrying.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Fact]
    public async Task Discovery_CancelDuringHello_ReturnsPromptly()
    {
        await using var server = new UaFaultProxy();
        using var cancellation = new CancellationTokenSource();
        var discovery = EndpointDiscoverer.DiscoverAsync(server.Url, 10000, cancellation.Token);
        await server.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(3));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => discovery.WaitAsync(TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public async Task RunAsync_SilentPeer_TimesOutAndDisconnects()
    {
        await using var server = new UaFaultProxy();
        await using var client = new UaClient(server.Url, new UaClientOptions
        {
            Timeout = 200, ReconnectMaxRetries = 0
        });
        var error = await Assert.ThrowsAsync<UaConnectionException>(
            () => client.RunAsync().WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.IsType<TimeoutException>(error.InnerException);
        Assert.Equal(ClientState.Disconnected, client.State);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(12)]
    public async Task RunAsync_PeerClosesHello_FailsBeforeRequestTimeout(int prefix)
    {
        await using var server = new UaFaultProxy(forwardPrefixBytes: prefix, closeAtFault: true);
        await using var client = new UaClient(server.Url, new UaClientOptions
        {
            Timeout = 10000, ReconnectMaxRetries = 0
        });
        var run = client.RunAsync();
        await Assert.ThrowsAsync<UaConnectionException>(() => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(ClientState.Disconnected, client.State);
    }
}
