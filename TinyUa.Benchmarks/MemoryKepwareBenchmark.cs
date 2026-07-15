using System.Diagnostics;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

/// <summary>
/// Long-running read/write workload for observing allocation, GC and TinyUa-owned pool usage.
/// Usage: dotnet run --project TinyUa.Benchmarks -- memory [url]
/// Stop with Ctrl+C.
/// </summary>
internal static class MemoryKepwareBenchmark
{
    private const int BatchSize = 10;

    internal static async Task RunAsync(string url)
    {
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stop.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;

        try
        {
            Console.WriteLine("TinyUa continuous memory / GC / pool monitor (None)");
            Console.WriteLine($"Server: {url}");
            Console.WriteLine("Each cycle batch-reads writable DemoCH/Data tags and writes their just-read values back.");
            Console.WriteLine("Press Ctrl+C to stop. ArrayPool.Shared does not expose its private cache or hit rate;");
            Console.WriteLine("the pool columns report every TinyUa-owned ArrayPool rental and the bounded encoder cache.");
            Console.WriteLine();

            await using var client = new UaClient(url, new UaClientOptions
            {
                ApplicationName = "TinyUa-Memory-Monitor",
                Timeout = 15000,
                WarmupOnConnect = true
            });
            await client.RunAsync().ConfigureAwait(false);

            var workload = await DiscoverWritableWorkloadAsync(client, stop.Token).ConfigureAwait(false);
            Console.WriteLine($"Monitoring {workload.Nodes.Length} verified-writable DemoCH/Data nodes after probing {workload.ProbedCount} candidates: {string.Join(", ", workload.Nodes.Select(node => node.ToString()))}");
            Console.WriteLine();

            await WarmupAsync(client, workload, stop.Token).ConfigureAwait(false);
            PrintHeader();
            await RunLoopAsync(client, workload, stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            Console.WriteLine();
            Console.WriteLine("Memory monitor stopped.");
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private static async Task RunLoopAsync(UaClient client, Workload workload, CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        var previous = MonitorSnapshot.Capture();
        var reportTimer = Stopwatch.StartNew();
        long readBatches = 0;
        long writeBatches = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            var readResults = await client.ReadAsync(workload.Nodes, cancellationToken: cancellationToken).ConfigureAwait(false);
            RequireGood(readResults, workload.Nodes.Length, "batch read");
            for (var i = 0; i < workload.WriteValues.Length; i++)
                workload.WriteValues[i].Value = new DataValue(readResults![i].DataValue!.Value);
            readBatches++;

            var writeResults = await client.WriteAsync(workload.WriteValues, cancellationToken).ConfigureAwait(false);
            RequireGood(writeResults, workload.WriteValues.Length, "batch write");
            writeBatches++;

            if (reportTimer.Elapsed < TimeSpan.FromSeconds(1))
                continue;

            var current = MonitorSnapshot.Capture();
            PrintReport(started.Elapsed, reportTimer.Elapsed, readBatches, writeBatches, workload.Nodes.Length, previous, current);
            previous = current;
            readBatches = 0;
            writeBatches = 0;
            reportTimer.Restart();
        }
    }

    private static async Task<Workload> DiscoverWritableWorkloadAsync(UaClient client, CancellationToken cancellationToken)
    {
        var objects = await BrowseChildrenAsync(client, "i=85", cancellationToken).ConfigureAwait(false);
        var demoChannel = objects.FirstOrDefault(IsNamed("DemoCH"))
            ?? throw new InvalidOperationException("Could not find DemoCH below Objects.");
        var dataFolder = (await BrowseChildrenAsync(client, demoChannel.NodeId, cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(IsNamed("Data"))
            ?? throw new InvalidOperationException($"Could not find Data below DemoCH ({demoChannel.NodeId}).");

        var variables = new List<ReferenceDescription>();
        await CollectVariablesAsync(client, dataFolder.NodeId, depth: 4, variables, limit: 100, cancellationToken).ConfigureAwait(false);
        if (variables.Count == 0)
            throw new InvalidOperationException("DemoCH/Data did not contain variable nodes.");

        var candidates = variables.Select(reference => (NodeId)reference.NodeId).ToArray();
        var values = await client.ReadAsync(candidates, cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("DemoCH/Data value read returned null.");
        var readableCandidates = Enumerable.Range(0, candidates.Length)
            .Where(index => values[index].StatusCode.IsGood && values[index].DataValue?.Value != null)
            .Select(index => new WriteValue
            {
                NodeId = candidates[index],
                Value = new DataValue(values[index].DataValue!.Value)
            })
            .ToArray();
        if (readableCandidates.Length == 0)
            throw new InvalidOperationException("DemoCH/Data did not expose a readable current value.");

        // UserAccessLevel is advisory on some KEPServer demo nodes. Probe the actual Write result
        // and continue scanning until a complete batch is formed instead of stopping at the first
        // ten metadata candidates.
        var confirmed = new List<WriteValue>(BatchSize);
        var probedCount = 0;
        foreach (var probeValues in readableCandidates.Chunk(BatchSize))
        {
            var batch = probeValues.ToArray();
            var probeResults = await client.WriteAsync(batch, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("DemoCH/Data writeability probe returned null.");
            if (probeResults.Length != batch.Length)
                throw new InvalidOperationException("DemoCH/Data writeability probe returned an unexpected result count.");

            probedCount += batch.Length;
            for (var index = 0; index < batch.Length && confirmed.Count < BatchSize; index++)
            {
                if (probeResults[index].StatusCode.IsGood)
                    confirmed.Add(batch[index]);
            }
            if (confirmed.Count == BatchSize)
                break;
        }

        if (confirmed.Count == 0)
            throw new InvalidOperationException("DemoCH/Data writeability probe did not return Good for any candidate.");

        return new Workload(
            confirmed.Select(value => value.NodeId).ToArray(),
            confirmed.ToArray(),
            probedCount);
    }

    private static async Task WarmupAsync(UaClient client, Workload workload, CancellationToken cancellationToken)
    {
        for (var iteration = 0; iteration < 20; iteration++)
        {
            var readResults = await client.ReadAsync(workload.Nodes, cancellationToken: cancellationToken).ConfigureAwait(false);
            RequireGood(readResults, workload.Nodes.Length, "warmup read");
            for (var i = 0; i < workload.WriteValues.Length; i++)
                workload.WriteValues[i].Value = new DataValue(readResults![i].DataValue!.Value);

            var writeResults = await client.WriteAsync(workload.WriteValues, cancellationToken).ConfigureAwait(false);
            RequireGood(writeResults, workload.WriteValues.Length, "warmup write");
        }
    }

    private static async Task<List<ReferenceDescription>> BrowseChildrenAsync(UaClient client, NodeId nodeId, CancellationToken cancellationToken)
    {
        var results = await client.BrowseAsync(nodeId, maxReferences: 1000, cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Browse {nodeId} returned null.");
        if (results.Length != 1 || !results[0].StatusCode.IsGood)
            throw new InvalidOperationException($"Browse {nodeId} failed.");
        return results[0].References?.ToList() ?? new List<ReferenceDescription>();
    }

    private static async Task CollectVariablesAsync(UaClient client, NodeId nodeId, int depth, List<ReferenceDescription> variables, int limit, CancellationToken cancellationToken)
    {
        if (depth < 0 || variables.Count >= limit)
            return;

        foreach (var child in await BrowseChildrenAsync(client, nodeId, cancellationToken).ConfigureAwait(false))
        {
            if (child.NodeClass == NodeClass.Variable)
            {
                variables.Add(child);
                if (variables.Count >= limit)
                    return;
            }
            else if (child.NodeClass == NodeClass.Object)
            {
                await CollectVariablesAsync(client, child.NodeId, depth - 1, variables, limit, cancellationToken).ConfigureAwait(false);
                if (variables.Count >= limit)
                    return;
            }
        }
    }

    private static Func<ReferenceDescription, bool> IsNamed(string name) => reference =>
        string.Equals(reference.BrowseName?.Name, name, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(reference.DisplayName?.Text, name, StringComparison.OrdinalIgnoreCase);

    private static void RequireGood(ReadResult[]? results, int expectedLength, string operation)
    {
        if (results == null || results.Length != expectedLength || results.Any(result => !result.StatusCode.IsGood))
            throw new InvalidOperationException($"{operation} returned null, an unexpected count, or a bad status.");
    }

    private static void RequireGood(WriteResult[]? results, int expectedLength, string operation)
    {
        if (results == null || results.Length != expectedLength || results.Any(result => !result.StatusCode.IsGood))
            throw new InvalidOperationException($"{operation} returned null, an unexpected count, or a bad status.");
    }

    private static void PrintHeader()
    {
        Console.WriteLine(" elapsed   read batches/s     write batches/s    alloc/s      GC delta      heap / fragment      array-pool rents/returns active/peak       encoder cache");
    }

    private static void PrintReport(TimeSpan elapsed, TimeSpan interval, long readBatches, long writeBatches, int batchSize, MonitorSnapshot previous, MonitorSnapshot current)
    {
        var seconds = interval.TotalSeconds;
        var allocated = current.Allocated - previous.Allocated;
        var rents = current.Buffers.Rents - previous.Buffers.Rents;
        var returns = current.Buffers.Returns - previous.Buffers.Returns;
        var encoderRents = current.Encoders.Rents - previous.Encoders.Rents;
        var encoderReuses = current.Encoders.Reuses - previous.Encoders.Reuses;

        Console.WriteLine(
            $" {elapsed:hh\\:mm\\:ss}  " +
            $"{readBatches / seconds,8:F0} ({readBatches * batchSize / seconds,6:F0} n/s)  " +
            $"{writeBatches / seconds,8:F0} ({writeBatches * batchSize / seconds,6:F0} n/s)  " +
            $"{FormatBytes((long)(allocated / seconds)),9}/s  " +
            $"+{current.Gen0 - previous.Gen0}/+{current.Gen1 - previous.Gen1}/+{current.Gen2 - previous.Gen2}  " +
            $"{FormatBytes(current.HeapSize)} / {FormatBytes(current.FragmentedBytes),8}  " +
            $"+{rents}/+{returns} {current.Buffers.ActivePooledBuffers}/{FormatBytes(current.Buffers.ActivePooledBytes)} " +
            $"peak {current.Buffers.PeakActivePooledBuffers}/{FormatBytes(current.Buffers.PeakActivePooledBytes)}  " +
            $"{current.Encoders.RetainedEncoders}/{FormatBytes(current.Encoders.RetainedCapacityBytes)} " +
            $"r{encoderRents} reuse{encoderReuses}");
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes:N0} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:N1} KiB";
        return $"{bytes / (1024d * 1024d):N2} MiB";
    }

    private sealed record Workload(NodeId[] Nodes, WriteValue[] WriteValues, int ProbedCount);

    private readonly record struct MonitorSnapshot(
        long Allocated,
        int Gen0,
        int Gen1,
        int Gen2,
        long HeapSize,
        long FragmentedBytes,
        BufferPoolStatistics Buffers,
        BinaryEncoderPoolStatistics Encoders)
    {
        internal static MonitorSnapshot Capture()
        {
            var memoryInfo = GC.GetGCMemoryInfo();
            return new MonitorSnapshot(
                GC.GetTotalAllocatedBytes(precise: false),
                GC.CollectionCount(0),
                GC.CollectionCount(1),
                GC.CollectionCount(2),
                memoryInfo.HeapSizeBytes,
                memoryInfo.FragmentedBytes,
                BufferLease.GetStatistics(),
                BinaryEncoderPool.GetStatistics());
        }
    }
}
