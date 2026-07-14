using System.Diagnostics;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

/// <summary>
/// Latency-oriented benchmark: Connect / Browse / Read / Write with percentile stats.
/// Usage: dotnet run --project TinyUa.Benchmarks -- latency [url]
/// </summary>
internal static class LatencyBenchmarks
{
    const string DefaultCertFile = @"C:\Users\skyal\Desktop\tinyuacerts\TinyUa Client.pfx";

    public static async Task RunAsync(string url)
    {
        var certFile = Environment.GetEnvironmentVariable("TINYUA_CLIENT_CERT") ?? DefaultCertFile;

        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║   TinyUa Performance Benchmark           ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine($"  Server:   {url}");
        Console.WriteLine($"  CPU:      {Environment.ProcessorCount} cores");
        Console.WriteLine($"  Runtime:  {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"  CertFile: {certFile}");
        Console.WriteLine();

        // ── 1. Connect latency ──
        Console.WriteLine("── 1. Connect Latency ──");
        const int connectIters = 5;
        var noneTimes = new double[connectIters];
        for (int i = 0; i < connectIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await using var c = await UaClient.ConnectTo(url).BuildAndRunAsync();
            sw.Stop();
            noneTimes[i] = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine($"  None     #{i + 1}: {noneTimes[i]:F1} ms");
        }

        var secureTimes = new double[connectIters];
        for (int i = 0; i < connectIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await using var c = await BuildSecureClientAsync(url, certFile);
            sw.Stop();
            secureTimes[i] = sw.Elapsed.TotalMilliseconds;
            Console.WriteLine($"  Secure   #{i + 1}: {secureTimes[i]:F1} ms");
        }
        PrintStats("  None  ", noneTimes);
        PrintStats("  Secure", secureTimes);
        Console.WriteLine();

        // ── 2-6: Use a persistent secure connection ──
        await using var client = await BuildSecureClientAsync(url, certFile);
        Console.WriteLine($"  Persistent secure connection: {client.IsConnected}, Session={client.SessionId}");
        Console.WriteLine();

        // Warmup: JIT all codec paths
        Console.WriteLine("  Warming up (100 reads)...");
        for (int i = 0; i < 100; i++)
            await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine();

        // ── 2. Browse latency ──
        Console.WriteLine("── 2. Browse Latency (Objects i=85) ──");
        const int browseIters = 20;
        var browseTimes = new double[browseIters];
        for (int i = 0; i < browseIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.BrowseAsync("i=85");
            sw.Stop();
            browseTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Browse", browseTimes);
        Console.WriteLine();

        // ── 3. Single Read latency ──
        Console.WriteLine("── 3. Single Read Latency (i=2258) ──");
        const int readIters = 1000;
        var readTimes = new double[readIters];
        for (int i = 0; i < readIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.ReadValueAsync<DateTime>("i=2258");
            sw.Stop();
            readTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Read  ", readTimes);
        Console.WriteLine();

        // ── 4. Batch Read latency ──
        Console.WriteLine("── 4. Batch Read Latency ──");
        NodeId[] baseNodes = { "i=2258", "i=2259", "i=2261", "i=2267", "i=2254", "i=2255", "i=2256", "i=2994" };

        foreach (var batchSize in new[] { 10, 50, 100 })
        {
            var nodeIds = new NodeId[batchSize];
            for (int i = 0; i < batchSize; i++)
                nodeIds[i] = baseNodes[i % baseNodes.Length];

            const int batchIters = 200;
            var batchTimes = new double[batchIters];
            for (int i = 0; i < batchIters; i++)
            {
                var sw = Stopwatch.StartNew();
                await client.ReadAsync(nodeIds);
                sw.Stop();
                batchTimes[i] = sw.Elapsed.TotalMilliseconds;
            }
            PrintStats($"  BatchRead  x{batchSize,3}", batchTimes);
        }
        Console.WriteLine();

        // ── 5. Single Write latency ──
        // Write to i=2258 (CurrentTime) — server will reject (read-only) but round-trip is measured
        Console.WriteLine("── 5. Single Write Latency (i=2258, read-only → round-trip) ──");
        const int writeIters = 500;
        var writeTimes = new double[writeIters];
        for (int i = 0; i < writeIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.WriteAsync("i=2258", DateTime.UtcNow);
            sw.Stop();
            writeTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Write ", writeTimes);
        Console.WriteLine();

        // ── 6. Batch Write latency ──
        Console.WriteLine("── 6. Batch Write Latency (read-only nodes → round-trip) ──");
        foreach (var batchSize in new[] { 10, 50 })
        {
            var writeValues = new WriteValue[batchSize];
            for (int i = 0; i < batchSize; i++)
            {
                writeValues[i] = new WriteValue
                {
                    NodeId = baseNodes[i % baseNodes.Length],
                    Value = new DataValue(new Variant(42))
                };
            }

            const int batchIters = 200;
            var batchTimes = new double[batchIters];
            for (int i = 0; i < batchIters; i++)
            {
                var sw = Stopwatch.StartNew();
                await client.WriteAsync(writeValues);
                sw.Stop();
                batchTimes[i] = sw.Elapsed.TotalMilliseconds;
            }
            PrintStats($"  BatchWrite x{batchSize,3}", batchTimes);
        }
        Console.WriteLine();

        Console.WriteLine("Benchmark complete.");
    }

    static async Task<UaClient> BuildSecureClientAsync(string url, string certFile)
    {
        return await UaClient
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
    }

    static void PrintStats(string label, double[] samples)
    {
        Array.Sort(samples);
        var sum = 0.0;
        foreach (var s in samples) sum += s;
        var avg = sum / samples.Length;
        var min = samples[0];
        var p50 = samples[samples.Length / 2];
        var p99 = samples[(int)(samples.Length * 0.99)];
        var max = samples[^1];
        Console.WriteLine($"{label}  avg={avg:F3}ms  min={min:F3}ms  p50={p50:F3}ms  p99={p99:F3}ms  max={max:F3}ms  (n={samples.Length})");
    }
}
