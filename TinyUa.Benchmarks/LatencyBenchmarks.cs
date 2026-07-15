using System.Diagnostics;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

/// <summary>
/// Latency-oriented benchmark: Connect / Browse / Read / Write with percentile stats.
/// Read/Write targets are real writable variables discovered under Objects.DemoCH.Data.
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

        // ── Discover writable variables under Objects.DemoCH.Data ──
        Console.WriteLine("── Discovering writable variables under Objects.DemoCH.Data ──");
        NodeId[] testNodes;
        DataValue[] writeBackValues;
        NodeId dataFolderId;
        try
        {
            (testNodes, writeBackValues, dataFolderId) = await DiscoverWritableNodesAsync(client);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ✗ Discovery failed: {ex.Message}");
            Console.WriteLine("  Falling back to standard server nodes (read-only — writes will be rejected).");
            testNodes = new NodeId[] { "i=2258", "i=2259", "i=2261", "i=2267", "i=2254", "i=2255", "i=2256", "i=2994" };
            writeBackValues = Array.Empty<DataValue>();
            dataFolderId = "i=85";
        }

        var writeableCount = writeBackValues.Length > 0 ? testNodes.Length : 0;
        Console.WriteLine($"  Using {testNodes.Length} variables for Read, {writeableCount} for Write (write-back original values).");
        if (testNodes.Length > 0)
            Console.WriteLine($"  Sample: {testNodes[0]} = {(writeBackValues.Length > 0 ? writeBackValues[0].Value?.Value : "(unread)")}");
        Console.WriteLine();

        // Warmup: JIT all codec paths
        Console.WriteLine("  Warming up (100 reads)...");
        for (int i = 0; i < 100; i++)
            await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine();

        // ── 2. Browse latency (DemoCH.Data folder) ──
        Console.WriteLine($"── 2. Browse Latency ({dataFolderId} DemoCH.Data) ──");
        const int browseIters = 20;
        var browseTimes = new double[browseIters];
        for (int i = 0; i < browseIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.BrowseAsync(dataFolderId, maxReferences: 100);
            sw.Stop();
            browseTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Browse", browseTimes);
        Console.WriteLine();

        // ── 3. Single Read latency ──
        // Control group: i=2258 (Server.CurrentTime, in-memory, no device I/O)
        Console.WriteLine($"── 3a. Single Read Latency — CONTROL (i=2258 Server.CurrentTime) ──");
        const int readIters = 1000;
        var ctrlReadTimes = new double[readIters];
        for (int i = 0; i < readIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.ReadValueAsync<DateTime>("i=2258");
            sw.Stop();
            ctrlReadTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Read[ctrl]", ctrlReadTimes);
        Console.WriteLine();

        Console.WriteLine($"── 3b. Single Read Latency — DEVICE ({testNodes[0]}) ──");
        var readTimes = new double[readIters];
        for (int i = 0; i < readIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.ReadValueAsync<object>(testNodes[0]);
            sw.Stop();
            readTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Read[dev] ", readTimes);
        Console.WriteLine();

        // ── 4. Batch Read latency ──
        Console.WriteLine("── 4. Batch Read Latency ──");
        foreach (var batchSize in new[] { 10, 50, 100 })
        {
            var actualSize = Math.Min(batchSize, testNodes.Length);
            var nodeIds = new NodeId[actualSize];
            for (int i = 0; i < actualSize; i++)
                nodeIds[i] = testNodes[i % testNodes.Length];

            const int batchIters = 200;
            var batchTimes = new double[batchIters];
            for (int i = 0; i < batchIters; i++)
            {
                var sw = Stopwatch.StartNew();
                await client.ReadAsync(nodeIds);
                sw.Stop();
                batchTimes[i] = sw.Elapsed.TotalMilliseconds;
            }
            PrintStats($"  BatchRead  x{actualSize,3}", batchTimes);
        }
        Console.WriteLine();

        if (writeBackValues.Length == 0)
        {
            Console.WriteLine("── 5/6. Write tests skipped (no writable variables discovered) ──");
            Console.WriteLine();
            Console.WriteLine("Benchmark complete.");
            return;
        }

        // ── 5. Single Write latency (write-back original value) ──
        // Control: i=2258 (read-only → BadUserAccessDenied, but round-trip measured)
        Console.WriteLine($"── 5a. Single Write Latency — CONTROL (i=2258, read-only round-trip) ──");
        const int writeIters = 500;
        var ctrlWriteTimes = new double[writeIters];
        for (int i = 0; i < writeIters; i++)
        {
            var sw = Stopwatch.StartNew();
            await client.WriteAsync("i=2258", DateTime.UtcNow);
            sw.Stop();
            ctrlWriteTimes[i] = sw.Elapsed.TotalMilliseconds;
        }
        PrintStats("  Write[ctrl]", ctrlWriteTimes);
        Console.WriteLine();

        Console.WriteLine($"── 5b. Single Write Latency — DEVICE ({testNodes[0]}, write-back original value) ──");
        var writeTimes = new double[writeIters];
        int devWriteOk = 0, devWriteBad = 0;
        for (int i = 0; i < writeIters; i++)
        {
            var sw = Stopwatch.StartNew();
            var wr = await client.WriteAsync(testNodes[0], writeBackValues[0].Value!.Value!);
            sw.Stop();
            writeTimes[i] = sw.Elapsed.TotalMilliseconds;
            if (wr != null && wr.StatusCode.IsGood) devWriteOk++; else devWriteBad++;
        }
        PrintStats("  Write[dev] ", writeTimes);
        Console.WriteLine($"         status: {devWriteOk} Good, {devWriteBad} Bad (of {writeIters})");
        Console.WriteLine();

        // ── 6. Batch Write latency (write-back original values) ──
        Console.WriteLine("── 6. Batch Write Latency (write-back original values) ──");
        foreach (var batchSize in new[] { 10, 50 })
        {
            var actualSize = Math.Min(batchSize, testNodes.Length);
            var writeValues = new WriteValue[actualSize];
            for (int i = 0; i < actualSize; i++)
            {
                // IMPORTANT: construct a fresh DataValue with ONLY the Value field.
                // Reusing the Read-returned DataValue carries SourceTimestamp/ServerTimestamp,
                // which KEPWARE rejects with BadWriteNotSupported (0x80730000).
                var originalValue = writeBackValues[i % writeBackValues.Length].Value!.Value!;
                writeValues[i] = new WriteValue
                {
                    NodeId = testNodes[i % testNodes.Length],
                    Value = new DataValue(new Variant(originalValue))
                };
            }

            const int batchIters = 200;
            var batchTimes = new double[batchIters];
            int batchWriteOk = 0, batchWriteBad = 0;
            string? firstBadStatus = null;
            for (int i = 0; i < batchIters; i++)
            {
                var sw = Stopwatch.StartNew();
                var wrs = await client.WriteAsync(writeValues);
                sw.Stop();
                batchTimes[i] = sw.Elapsed.TotalMilliseconds;
                if (wrs != null)
                {
                    foreach (var wr in wrs)
                    {
                        if (wr.StatusCode.IsGood) batchWriteOk++;
                        else
                        {
                            batchWriteBad++;
                            firstBadStatus ??= wr.StatusCode.ToString();
                        }
                    }
                }
            }
            PrintStats($"  BatchWrite x{actualSize,3}", batchTimes);
            Console.WriteLine($"         status: {batchWriteOk} Good, {batchWriteBad} Bad{(firstBadStatus != null ? $" (e.g. {firstBadStatus})" : "")}");
        }
        Console.WriteLine();

        Console.WriteLine("Benchmark complete.");
    }

    /// <summary>
    /// Discover writable variables under Objects → DemoCH → Data.
    /// Returns (nodeIds, originalDataValues, dataFolderNodeId) for use in Read/Write tests.
    /// Write-back uses the original values so KEPWARE data is not mutated.
    /// </summary>
    static async Task<(NodeId[] nodes, DataValue[] originalValues, NodeId dataFolderId)> DiscoverWritableNodesAsync(UaClient client)
    {
        // Browse Objects (i=85) → find DemoCH
        var objectsRefs = await BrowseAllAsync(client, "i=85");
        var demoCh = objectsRefs.FirstOrDefault(r =>
            r.DisplayName?.Text?.Equals("DemoCH", StringComparison.OrdinalIgnoreCase) == true)
            ?? throw new InvalidOperationException("DemoCH not found under Objects(i=85)");
        Console.WriteLine($"  Found DemoCH: {demoCh.NodeId}");

        // Browse DemoCH → find Data
        var demoChRefs = await BrowseAllAsync(client, demoCh.NodeId);
        var data = demoChRefs.FirstOrDefault(r =>
            r.DisplayName?.Text?.Equals("Data", StringComparison.OrdinalIgnoreCase) == true)
            ?? throw new InvalidOperationException("Data not found under DemoCH");
        Console.WriteLine($"  Found Data: {data.NodeId}");

        // Browse Data → collect all Variable nodes (NodeClass == 2)
        var dataRefs = await BrowseAllAsync(client, data.NodeId);
        var variableNodes = dataRefs
            .Where(r => (int)r.NodeClass == 2)
            .Select(r => r.NodeId)
            .ToList();
        Console.WriteLine($"  Found {variableNodes.Count} Variable nodes under Data");

        if (variableNodes.Count == 0)
            throw new InvalidOperationException("No Variable nodes under DemoCH.Data");

        // Take up to 100 nodes for testing
        var testNodes = variableNodes.Take(100).ToArray();

        // Pre-read current values for write-back (so we don't mutate KEPWARE data)
        var readBack = await client.ReadAsync(testNodes)
            ?? throw new InvalidOperationException("ReadAsync returned null during discovery");

        var originalValues = new DataValue[testNodes.Length];
        var writableIndexes = new List<int>();
        for (int i = 0; i < testNodes.Length; i++)
        {
            originalValues[i] = readBack[i].DataValue!;
            if (readBack[i].StatusCode.IsGood && originalValues[i].Value?.Value != null)
                writableIndexes.Add(i);
        }

        // Verify writability: try writing back the original value to the first candidate
        // and keep only nodes where the write succeeds with Good status.
        var verifiedNodes = new List<NodeId>();
        var verifiedValues = new List<DataValue>();
        int probeCount = Math.Min(writableIndexes.Count, 20); // probe first 20 to keep discovery fast
        foreach (var idx in writableIndexes.Take(probeCount))
        {
            try
            {
                var w = await client.WriteAsync(testNodes[idx], originalValues[idx].Value!.Value!);
                if (w != null && w.StatusCode.IsGood)
                {
                    verifiedNodes.Add(testNodes[idx]);
                    verifiedValues.Add(originalValues[idx]);
                }
            }
            catch { /* not writable */ }
        }

        if (verifiedNodes.Count == 0)
        {
            // Fallback: use all read-Good nodes even if write probe failed (some servers
            // reject write during discovery due to timing). Read tests still valid.
            Console.WriteLine($"  Write probe failed for all {probeCount} candidates — using read-Good nodes for Read-only tests.");
            return (testNodes, Array.Empty<DataValue>(), data.NodeId);
        }

        Console.WriteLine($"  Verified {verifiedNodes.Count} writable nodes (probed {probeCount}).");
        return (verifiedNodes.ToArray(), verifiedValues.ToArray(), data.NodeId);
    }

    static async Task<List<ReferenceDescription>> BrowseAllAsync(UaClient client, NodeId nodeId)
    {
        var all = new List<ReferenceDescription>();
        byte[]? cp = null;
        do
        {
            var results = cp == null
                ? await client.BrowseAsync(nodeId, maxReferences: 100)
                : await client.BrowseNextAsync(cp);
            if (results == null || results.Length == 0) break;
            var refs = results[0].References;
            if (refs != null) all.AddRange(refs);
            cp = results[0].ContinuationPoint;
        } while (cp != null && cp.Length > 0);
        return all;
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
