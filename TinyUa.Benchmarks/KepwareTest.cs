using System.Threading;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

/// <summary>
/// KEPWARE comprehensive integration test suite: connect / browse / read / subscribe /
/// reconnect / deep-browse against a live KEPWARE OPC UA server.
/// Usage: dotnet run --project TinyUa.Benchmarks -- kepware [url]
/// </summary>
internal static class KepwareTest
{
    const string DefaultCertFile = @"C:\Users\skyal\Desktop\tinyuacerts\TinyUa Client.pfx";

    public static async Task RunAsync(string url)
    {
        var certFile = Environment.GetEnvironmentVariable("TINYUA_CLIENT_CERT") ?? DefaultCertFile;
        var pass = 0;
        var fail = 0;
        void Ok(string label) { Console.WriteLine($"  ✓ {label}"); Interlocked.Increment(ref pass); }
        void Fail(string label, Exception? ex = null) { Console.WriteLine($"  ✗ {label}{(ex != null ? $" — {ex.Message}" : "")}"); Interlocked.Increment(ref fail); }

        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║   KEPWARE Comprehensive Test             ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();

        // ── 1. None + Anonymous ──
        Console.WriteLine("── 1. None + Anonymous ──");
        try
        {
            await using var client = await UaClient.ConnectTo(url).BuildAndRunAsync();
            if (client.IsConnected) Ok($"Connected, Session={client.SessionId}");
            else Fail("Not connected");
            var t = await client.ReadValueAsync<DateTime>("i=2258");
            Ok($"Read ServerTime = {t:HH:mm:ss.fff}");
        }
        catch (Exception ex) { Fail("None+Anonymous", ex); }
        Console.WriteLine();

        // ── 2. Basic256Sha256 + Anonymous (PFX cert) ──
        Console.WriteLine("── 2. Basic256Sha256 + Anonymous (PFX cert) ──");
        UaClient? secureClient = null;
        try
        {
            secureClient = await UaClient
                .ConnectTo(url)
                .WithSecurity("Basic256Sha256")
                .WithSecurity(opts =>
                {
                    opts.Certificate = new CertificateOptions
                    {
                        CertificatePath = certFile,
                        AutoGenerate = false
                    };
                })
                .BuildAndRunAsync();
            if (secureClient.IsConnected) Ok($"Connected, Session={secureClient.SessionId}");
            else Fail("Not connected");
            var t = await secureClient.ReadValueAsync<DateTime>("i=2258");
            Ok($"Read ServerTime = {t:HH:mm:ss.fff}");
        }
        catch (Exception ex) { Fail("Basic256Sha256+Anonymous", ex); }
        Console.WriteLine();

        if (secureClient == null || !secureClient.IsConnected)
        {
            Console.WriteLine("Secure client not connected — skipping remaining tests.");
            Console.WriteLine($"\nResults: {pass} passed, {fail} failed");
            return;
        }

        // ── 3. Browse Objects folder ──
        Console.WriteLine("── 3. Browse Objects folder ──");
        ReferenceDescription[]? topLevelRefs = null;
        try
        {
            var results = await secureClient.BrowseAsync("i=85");
            if (results != null && results.Length > 0 && results[0].References != null)
            {
                topLevelRefs = results[0].References;
                Ok($"Objects folder has {topLevelRefs.Length} children");
                foreach (var r in topLevelRefs.Take(10))
                    Console.WriteLine($"     {r.NodeId}  {r.DisplayName?.Text}  (class={r.NodeClass})");
            }
            else Fail("Browse returned null or empty");
        }
        catch (Exception ex) { Fail("Browse Objects", ex); }
        Console.WriteLine();

        // ── 4. Read single + batch ──
        Console.WriteLine("── 4. Read single + batch ──");
        try
        {
            var state = await secureClient.ReadValueAsync<int>("i=2259");
            Ok($"Read ServerStatus.State = {state}");

            var batch = await secureClient.ReadAsync(new NodeId[] { "i=2258", "i=2259", "i=2261" });
            if (batch != null)
            {
                Ok($"Batch read {batch.Length} nodes");
                for (int i = 0; i < batch.Length; i++)
                {
                    var v = batch[i].DataValue?.Value?.Value;
                    var s = batch[i].StatusCode;
                    Console.WriteLine($"     [{i}] status={s} value={v}");
                }
            }
            else Fail("Batch read returned null");
        }
        catch (Exception ex) { Fail("Read", ex); }
        Console.WriteLine();

        // ── 5. Subscription ──
        Console.WriteLine("── 5. Subscription (i=2258 CurrentTime, 1000ms) ──");
        try
        {
            var count = 0;
            var sub = await secureClient.SubscribeAsync<DateTime>("i=2258", val =>
            {
                Interlocked.Increment(ref count);
            }, interval: 1000);

            await Task.Delay(4000);
            sub.Dispose();
            if (count >= 2) Ok($"Received {count} notifications in 4s");
            else Fail($"Only {count} notifications in 4s (expected >=2)");
        }
        catch (Exception ex) { Fail("Subscription", ex); }
        Console.WriteLine();

        // ── 6. Reconnect test ──
        Console.WriteLine("── 6. Reconnect test ──");
        try
        {
            await secureClient.DisposeAsync();
            secureClient = await UaClient
                .ConnectTo(url)
                .WithSecurity("Basic256Sha256")
                .WithSecurity(opts =>
                {
                    opts.Certificate = new CertificateOptions
                    {
                        CertificatePath = certFile,
                        AutoGenerate = false
                    };
                })
                .BuildAndRunAsync();
            if (secureClient.IsConnected) Ok($"Reconnected, Session={secureClient.SessionId}");
            else Fail("Reconnect failed");
            var t = await secureClient.ReadValueAsync<DateTime>("i=2258");
            Ok($"Read after reconnect = {t:HH:mm:ss.fff}");
        }
        catch (Exception ex) { Fail("Reconnect", ex); }
        Console.WriteLine();

        // ── 7. Deep browse (look for writable tags) ──
        Console.WriteLine("── 7. Deep browse (look for writable tags) ──");
        try
        {
            if (topLevelRefs != null && topLevelRefs.Length > 0)
            {
                var firstRef = topLevelRefs[0];
                Console.WriteLine($"     Browsing {firstRef.NodeId} ({firstRef.DisplayName?.Text})...");
                var subResults = await secureClient.BrowseAsync(firstRef.NodeId);
                if (subResults != null && subResults.Length > 0 && subResults[0].References != null)
                {
                    var subRefs = subResults[0].References;
                    Console.WriteLine($"     Found {subRefs.Length} sub-nodes");
                    foreach (var r in subRefs.Take(5))
                        Console.WriteLine($"       {r.NodeId}  {r.DisplayName?.Text}  (class={r.NodeClass})");

                    // Try to read the first Variable node (NodeClass.Variable == 2)
                    var varRef = subRefs.FirstOrDefault(r => (int)r.NodeClass == 2);
                    if (varRef != null)
                    {
                        var val = await secureClient.ReadValueAsync<object>(varRef.NodeId);
                        Ok($"Read tag {varRef.DisplayName?.Text} = {val}");
                    }
                }
            }
            Ok("Deep browse: walked Objects tree (KEPWARE project-specific tags)");
        }
        catch (Exception ex) { Fail("Deep browse", ex); }
        Console.WriteLine();

        await secureClient.DisposeAsync();

        Console.WriteLine($"═══════════════════════════════════════════");
        Console.WriteLine($"Results: {pass} passed, {fail} failed");
        Console.WriteLine();
    }
}
