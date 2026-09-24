using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Client;
using TinyUa.Client.Connection;
using TinyUa.Client.Security;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using TinyUa.Testing;

namespace TinyUa.Security.Tests;

[Collection("SecureServer")]
public class AuditLifecycleRegressionTests
{
    private readonly OpcfSecureServerFixture _server;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;
    public AuditLifecycleRegressionTests(OpcfSecureServerFixture server, Xunit.Abstractions.ITestOutputHelper output)
    { _server = server; _output = output; }
    private ILogger Logger => new DelegateLogger((level, ex, message) => _output.WriteLine($"{level}: {message} {ex}"), LogLevel.Debug);

    private static UaClientOptions Options() => new()
    {
        Timeout = 5000,
        ReconnectMaxRetries = 0,
        WarmupOnConnect = false,
        SessionKeepAliveIntervalMs = -1,
        ReconnectInitialDelayMs = 20,
        ReconnectMaxDelayMs = 50
    };

    [Fact]
    public async Task ConcurrentRunWaitsAndSecondaryCancellationDoesNotCancelOwner()
    {
        await using var proxy = new UaFaultProxy();
        await using var client = new UaClient(proxy.Url, Options());
        using var ownerCancellation = new CancellationTokenSource();
        var first = client.RunAsync(ownerCancellation.Token);
        await proxy.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var waiterCancellation = new CancellationTokenSource();
        var second = client.RunAsync(waiterCancellation.Token);
        Assert.False(second.IsCompleted);
        waiterCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);
        Assert.False(first.IsCompleted);
        var stops = Enumerable.Range(0, 16).Select(_ => client.StopAsync()).ToArray();
        await Task.WhenAll(stops).WaitAsync(TimeSpan.FromSeconds(3));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.Equal(ClientState.Disconnected, client.State);
        Assert.Equal(1, proxy.Accepted);
    }

    [Theory]
    [InlineData("Read")]
    [InlineData("Browse")]
    [InlineData("Write")]
    [InlineData("Subscribe")]
    public async Task PublicOperationsCancelWhileServerResponseIsStalled(string operation)
    {
        await using var proxy = new UaFaultProxy(_server.EndpointUrl, stallResponse: 5);
        await using var client = new UaClient(proxy.Url, Options());
        await client.RunAsync();
        using var cancel = new CancellationTokenSource();
        Task pending = operation switch
        {
            "Read" => client.ReadAsync(new NodeId(2259u), cancellationToken: cancel.Token),
            "Browse" => client.BrowseAsync(new NodeId(85u), cancellationToken: cancel.Token),
            // The reference server's read-only standard node cannot modify a device.
            "Write" => client.WriteAsync(new NodeId(2259u), 0, cancellationToken: cancel.Token),
            _ => client.SubscribeAsync(new NodeId(2258u), (_, _, _) => { }, cancellationToken: cancel.Token)
        };
        await proxy.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var watch = Stopwatch.StartNew();
        cancel.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(cancel.Token, error.CancellationToken);
        Assert.True(watch.ElapsedMilliseconds < 1500);
        proxy.DropConnections();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecureReactivationUsesLatestNonceAndOriginalIdentity(bool username)
    {
        var options = Options();
        options.ReconnectMaxRetries = 3;
        options.Security = new SecurityOptions
        {
            Policy = "Basic256Sha256",
            Mode = MessageSecurityMode.SignAndEncrypt,
            AutoAcceptServerCertificate = true,
            UserIdentity = username ? new UserIdentityOptions
            {
                Type = UserTokenType.UserName,
                Username = OpcfSecureServerFixture.UserName,
                Password = OpcfSecureServerFixture.UserPassword
            } : new UserIdentityOptions()
        };
        await using var connection = new UaConnection(5000, Logger);
        var orchestrator = new ConnectionOrchestrator(connection, options, Logger);
        await orchestrator.ConnectAsync(_server.EndpointUrl);
        var session = connection.SessionId;
        using var engine = new ReconnectEngine(connection, options, Logger);
        engine.OnSessionEstablished(session!, connection.AuthenticationToken!);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            await connection.DisconnectAsync();
            Assert.True(await engine.ReconnectAsync(_server.EndpointUrl, _ => Task.FromResult<Subscription?>(null)));
            Assert.Equal(session, connection.SessionId);
            var values = await connection.ReadAsync(new[] { new NodeId(2259u) });
            Assert.True(values![0].StatusCode.IsGood);
        }
        await engine.StopAsync();
        await connection.CloseSessionAsync();
    }

    [Fact]
    public async Task RebuildPreservesPublicHandlesAndDoesNotResurrectDeletedItems()
    {
        await using var proxy = new UaFaultProxy(_server.EndpointUrl, int.MaxValue);
        var options = Options();
        options.ReconnectMaxRetries = 3;
        options.MaxPublishRequests = 1;
        await using var client = new UaClient(proxy.Url, options);
        await client.RunAsync();
        var removed = await client.SubscribeAsync(new NodeId(2259u), (_, _, _) => { }, 100);
        var current = await client.SubscribeAsync(new NodeId(2258u), (_, _, _) => { }, 100);
        Assert.Same(removed.Subscription, current.Subscription);
        var sub = current.Subscription;
        Assert.True((await client.DeleteMonitoredItemsAsync(sub, new[] { removed.MonitoredItemId }))[0].IsGood);
        sub.StopPublishing();
        var recovered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.SubscriptionsRecovered += lossless => recovered.TrySetResult(lossless);
        var connection = (UaConnection)typeof(UaClient).GetField("_client", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        await connection.CloseSessionAsync();
        proxy.DropConnections();
        Assert.False(await recovered.Task.WaitAsync(TimeSpan.FromSeconds(12)));
        Assert.Single(sub.MonitoredItems);
        Assert.DoesNotContain(sub.MonitoredItems.Values, i => i.MonitoredItemId == removed.MonitoredItemId);
        Assert.Contains(sub.MonitoredItems.Values, i => i.MonitoredItemId == current.MonitoredItemId);
        Assert.True((await client.DeleteMonitoredItemsAsync(sub, new[] { current.MonitoredItemId }))[0].IsGood);
        Assert.Empty(sub.MonitoredItems);
        sub.Dispose();
        var fresh = await client.SubscribeAsync(new NodeId(2258u), (_, _, _) => { }, 100);
        Assert.NotSame(sub, fresh.Subscription);
    }

    [Fact]
    public async Task WriteWhoseResponseIsLostIsNeverReplayedAfterReconnect()
    {
        await using var proxy = new UaFaultProxy(_server.EndpointUrl, 5, closeAtFault: true);
        var options = Options();
        options.ReconnectMaxRetries = 3;
        await using var client = new UaClient(proxy.Url, options);
        await client.RunAsync();
        await Assert.ThrowsAnyAsync<Exception>(() => client.WriteAsync(new NodeId(2259u), 0));
        proxy.StallResponse = int.MaxValue;
        // Waiting through the subsequent Read proves recovery completed without replaying Write.
        var read = await client.ReadAsync(new NodeId(2259u));
        Assert.True(read!.StatusCode.IsGood);
        Assert.Equal(1, proxy.UnsecuredWriteRequests);
    }

    [Fact]
    public async Task StopCancelsSilentReconnectAndCannotReturnToConnected()
    {
        await using var proxy = new UaFaultProxy(_server.EndpointUrl, int.MaxValue);
        var options = Options();
        options.ReconnectMaxRetries = -1;
        await using var client = new UaClient(proxy.Url, options, Logger);
        await client.RunAsync();
        proxy.StallResponse = 1;
        proxy.DropConnections();
        await proxy.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await client.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(ClientState.Disconnected, client.State);
        proxy.StallResponse = int.MaxValue;
        await client.RunAsync();
        Assert.True(client.IsConnected);
    }

    [Theory]
    [InlineData("Basic256Sha256", false)]
    [InlineData("Aes256_Sha256_RsaPss", true)]
    public void X509IdentitySignsWithConfiguredUserCertificate(string policyName, bool pss)
    {
        var file = Path.Combine(Path.GetTempPath(), $"tinyua-user-{Guid.NewGuid():N}.pfx");
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=Separate User", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        try
        {
            File.WriteAllBytes(file, certificate.Export(X509ContentType.Pfx, "test-password"));
            var response = new CreateSessionResponse
            {
                ServerCertificate = _server.ServerCertificate!.RawData,
                ServerNonce = RandomNumberGenerator.GetBytes(32),
                ServerEndpoints = new[] { new EndpointDescription
                {
                    SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None", SecurityMode = MessageSecurityMode.None,
                    UserIdentityTokens = new[] { new UserTokenPolicy
                    {
                        TokenType = UserTokenType.Certificate, PolicyId = "user-x509",
                        SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#" + policyName
                    } }
                } }
            };
            var identity = UserIdentityFactory.Build(new UserIdentityOptions
            {
                Type = UserTokenType.Certificate,
                CertificatePath = file,
                PrivateKeyPassword = "test-password"
            }, response, new NoneSecurityPolicy(), null);
            Assert.Equal(certificate.RawData, identity.IssuedId);
            Assert.Equal("user-x509", identity.PolicyId);
            Assert.True(key.VerifyData(response.ServerCertificate.Concat(response.ServerNonce).ToArray(), identity.SignatureData!,
                HashAlgorithmName.SHA256, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1));
        }
        finally { File.Delete(file); }
    }
}
