using System.Collections.Concurrent;
using System.Diagnostics;
using TinyUa.Client;
using TinyUa.Client.Discovery;
using TinyUa.Core.Types;
using TinyUa.Testing;

namespace TinyUa.Benchmarks;

internal static class ConnectionFaultBenchmark
{
    private static UaClientOptions Options() => new()
    {
        ApplicationName = "TinyUa-Fault-Verification", Timeout = 10000,
        ReconnectMaxRetries = 0, SessionKeepAliveIntervalMs = -1,
        SessionTimeout = 30000
    };

    internal static async Task RunAsync(string url)
    {
        var passed = 0;
        var failed = 0;
        async Task Case(string name, Func<Task> test)
        {
            var clock = Stopwatch.StartNew();
            try
            {
                await test();
                Console.WriteLine($"PASS {name} ({clock.Elapsed.TotalMilliseconds:F1} ms)");
                passed++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAIL {name} ({clock.Elapsed.TotalMilliseconds:F1} ms): {ex}");
                failed++;
            }
        }

        Console.WriteLine($"Connection fault verification: {url}");
        Console.WriteLine("Only loopback proxy connections are interrupted; server values are not written.");
        var endpoints = await EndpointDiscoverer.DiscoverAsync(url, 5000);
        foreach (var endpoint in endpoints)
            Console.WriteLine($"  Endpoint: {endpoint.DisplayText}");

        await Case("Cancel unreachable TCP connection attempt", async () =>
        {
            await using var client = new UaClient("opc.tcp://192.0.2.1:4840", Options());
            using var ct = new CancellationTokenSource();
            var run = client.RunAsync(ct.Token);
            await Task.Delay(150);
            Require(!run.IsCompleted, "Network rejected the address immediately; no pending TCP connect to test.");
            var clock = Stopwatch.StartNew();
            ct.Cancel();
            try
            {
                await run.WaitAsync(TimeSpan.FromSeconds(2));
                throw new InvalidOperationException("Cancelled connect returned success.");
            }
            catch (OperationCanceledException ex) when (ex.CancellationToken == ct.Token) { }
            Require(client.State == ClientState.Disconnected, "Cancelled TCP state not reset.");
            Console.WriteLine($"  TCP cancellation={clock.Elapsed.TotalMilliseconds:F2} ms");
        });

        await Case("Cancel token after successful connection keeps session usable", async () =>
        {
            await using var client = new UaClient(url, Options());
            using var ct = new CancellationTokenSource(15000);
            await client.RunAsync(ct.Token);
            ct.Cancel();
            Require(client.IsConnected, "Successful session was cancelled.");
            Require((await client.ReadAsync(new NodeId(2258u)))?.StatusCode.IsGood == true, "Read failed.");
        });

        foreach (var (frame, prefix, label) in new[]
        {
            (1, 0, "HEL/ACK no response"), (1, 4, "partial ACK header"), (1, 12, "partial ACK body"),
            (2, 0, "OpenSecureChannel"), (3, 0, "CreateSession"), (4, 0, "ActivateSession"),
            (5, 0, "warmup Read")
        })
            await Case($"Cancel during {label}, then reconnect same client", () =>
                CancelHandshakeAsync(url, frame, prefix));

        await Case("Mixed valid/invalid batch read and invalid browse preserve connection", async () =>
        {
            await using var client = new UaClient(url, Options());
            using var ct = new CancellationTokenSource(15000);
            await client.RunAsync(ct.Token);
            NodeId missing = $"ns=2;s=TinyUa.Missing.{Guid.NewGuid():N}";
            var read = await client.ReadAsync(new NodeId[] { new(2258u), missing, new(2259u) });
            Require(read is { Length: 3 } && read[0].StatusCode.IsGood && read[1].StatusCode.IsBad && read[2].StatusCode.IsGood,
                "Mixed read did not retain per-node statuses.");
            var browse = await client.BrowseAsync(missing);
            Require(browse is { Length: 1 } && browse[0].StatusCode.IsBad, "Missing node browse unexpectedly succeeded.");
            Console.WriteLine($"  Expected errors: Read={read![1].StatusCode.GetStatusText()}, Browse={browse![0].StatusCode.GetStatusText()}");
            Require(client.IsConnected, "Bad node status disconnected client.");
        });

        await Case("8 concurrent readers, 160 requests", async () =>
        {
            await using var client = new UaClient(url, Options());
            using var ct = new CancellationTokenSource(15000);
            await client.RunAsync(ct.Token);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
            {
                for (var i = 0; i < 20; i++)
                    Require((await client.ReadAsync(new NodeId(2258u)))?.StatusCode.IsGood == true, "Concurrent read failed.");
            })).WaitAsync(TimeSpan.FromSeconds(15));
        });

        await Case("Broken TCP connection recovers session and subscription", async () =>
        {
            await using var proxy = new UaFaultProxy(url, stallResponse: 0);
            var options = Options();
            options.ReconnectMaxRetries = 3;
            options.ReconnectInitialDelayMs = 100;
            await using var client = new UaClient(proxy.Url, options);
            using var ct = new CancellationTokenSource(15000);
            var states = new ConcurrentQueue<ClientState>();
            client.StateChanged += states.Enqueue;
            await client.RunAsync(ct.Token);
            var recovered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.SubscriptionsRecovered += lossless => recovered.TrySetResult(lossless);
            var notifications = 0;
            using var subscription = await client.SubscribeAsync<DateTime>("i=2258", _ => Interlocked.Increment(ref notifications), 250);
            await WaitUntilAsync(() => Volatile.Read(ref notifications) >= 2);
            proxy.DropConnections();
            var lossless = await recovered.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var afterRecovery = Volatile.Read(ref notifications);
            await WaitUntilAsync(() => Volatile.Read(ref notifications) > afterRecovery);
            Require(client.IsConnected && states.Contains(ClientState.Reconnecting), "No reconnect state observed.");
            Require((await client.ReadAsync(new NodeId(2258u)))?.StatusCode.IsGood == true, "Read after recovery failed.");
            Console.WriteLine($"  recoveredLosslessly={lossless}, callbacks={notifications}, states={string.Join(",", states)}");
        });

        var cert = Environment.GetEnvironmentVariable("TINYUA_CLIENT_CERT")
            ?? @"C:\Users\skyal\Desktop\tinyuacerts\TinyUa Client.pfx";
        foreach (var endpoint in endpoints.Where(e => e.IsSecure))
        {
            var legacyPolicy = endpoint.SecurityPolicy is "Basic128Rsa15" or "Basic256";
            await Case($"Security {endpoint.SecurityPolicy}/{endpoint.SecurityMode}" +
                (legacyPolicy ? " (expected unsupported policy rejection)" : ""), async () =>
            {
                var options = Options();
                options.Security.Policy = endpoint.SecurityPolicy;
                options.Security.Mode = endpoint.SecurityMode;
                options.Security.Certificate = new CertificateOptions { CertificatePath = cert, AutoGenerate = false };
                await using var client = new UaClient(url, options);
                using var ct = new CancellationTokenSource(15000);
                if (legacyPolicy)
                {
                    try
                    {
                        await client.RunAsync(ct.Token);
                        throw new InvalidOperationException("Unsupported legacy policy unexpectedly succeeded.");
                    }
                    catch (UaConnectionException ex) when (ex.InnerException is ArgumentException argument &&
                        argument.Message.Contains("Unsupported security policy"))
                    {
                        Require(client.State == ClientState.Disconnected, "Failed secure connection did not reset state.");
                        Console.WriteLine($"  Expected rejection: {argument.Message}");
                    }
                    return;
                }
                await client.RunAsync(ct.Token);
                Require((await client.ReadAsync(new NodeId(2258u)))?.StatusCode.IsGood == true, "Secure read failed.");
            });

            if (!legacyPolicy)
                await Case($"Cancel automatic GetEndpoints for {endpoint.SecurityPolicy}, then reconnect", () =>
                    CancelHandshakeAsync(url, 3, 0, new SecurityOptions
                    {
                        Policy = endpoint.SecurityPolicy, Mode = endpoint.SecurityMode,
                        Certificate = new CertificateOptions { CertificatePath = cert, AutoGenerate = false }
                    }));
        }

        Console.WriteLine($"Fault verification results: {passed} passed, {failed} failed.");
        if (failed > 0) throw new InvalidOperationException($"{failed} fault verification case(s) failed.");
    }

    private static async Task CancelHandshakeAsync(string url, int response, int prefix, SecurityOptions? security = null)
    {
        await using var proxy = new UaFaultProxy(url, response, prefix);
        var options = Options();
        if (security != null) options.Security = security;
        await using var client = new UaClient(proxy.Url, options);
        using var ct = new CancellationTokenSource();
        var run = client.RunAsync(ct.Token);
        try
        {
            await proxy.FaultReached.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var clock = Stopwatch.StartNew();
            ct.Cancel();
            try
            {
                await run.WaitAsync(TimeSpan.FromSeconds(2));
                throw new InvalidOperationException("Cancelled RunAsync returned success.");
            }
            catch (OperationCanceledException ex) when (ex.CancellationToken == ct.Token) { }
            Console.WriteLine($"  cancellation={clock.Elapsed.TotalMilliseconds:F2} ms");
            Require(client.State == ClientState.Disconnected && client.SessionId == null, "Cancelled state/session not cleaned up.");
            proxy.StallResponse = 0;
            using var retry = new CancellationTokenSource(10000);
            await client.RunAsync(retry.Token);
            Require(client.IsConnected, "Same instance failed to reconnect.");
            Require((await client.ReadAsync(new NodeId(2258u)))?.StatusCode.IsGood == true, "Read after cancelled attempt failed.");
        }
        finally
        {
            ct.Cancel();
            if (!run.IsCompleted) proxy.DropConnections();
            try { await run.WaitAsync(TimeSpan.FromSeconds(3)); } catch { }
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(10000);
        while (!condition()) await Task.Delay(50, deadline.Token);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
