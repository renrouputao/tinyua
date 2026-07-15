using System.Collections.Concurrent;
using System.Diagnostics;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

/// <summary>
/// Live None-security verification and latency measurement for a KEPServer endpoint.
/// Standard OPC UA server nodes are deliberately used for writes: they are read-only, so this
/// exercises batch Write encoding and result handling without changing a project tag.
/// Usage: dotnet run --project TinyUa.Benchmarks -- none [url]
/// </summary>
internal static class NoneKepwareBenchmark
{
    private static readonly NodeId[] ReadNodes =
    {
        "i=2258", "i=2259", "i=2261", "i=2267", "i=2254", "i=2255", "i=2256", "i=2994"
    };

    public static async Task RunAsync(string url)
    {
        Console.WriteLine("TinyUa None KEPServer Verification");
        Console.WriteLine($"Server: {url}");
        Console.WriteLine("Standard-node writes are read-only checks; DemoCH/Data writes preserve each tag's current value.");
        Console.WriteLine();

        var connectTimes = new List<double>();
        for (var i = 0; i < 5; i++)
        {
            var sw = Stopwatch.StartNew();
            await using var client = await UaClient.ConnectTo(url)
                .WithRequestTimeout(15000)
                .BuildAndRunAsync();
            sw.Stop();
            connectTimes.Add(sw.Elapsed.TotalMilliseconds);
            Require(client.IsConnected, "Connection did not reach Connected state.");
        }
        PrintStats("Connect", connectTimes);

        await using var persistent = new UaClient(url, new UaClientOptions
        {
            ApplicationName = "TinyUa-None-Verify",
            Timeout = 15000,
            MaxPublishRequests = 2,
            SubscriptionDispatch = new SubscriptionDispatchOptions
            {
                QueueCapacity = 2,
                OverflowPolicy = NotificationOverflowPolicy.Wait
            }
        });
        await persistent.RunAsync();
        Require(persistent.IsConnected, "Persistent None client did not connect.");

        var browseTimes = new List<double>();
        for (var i = 0; i < 30; i++)
        {
            var sw = Stopwatch.StartNew();
            var results = await persistent.BrowseAsync("i=85");
            sw.Stop();
            Require(results is { Length: > 0 } && results[0].References is { Length: > 0 }, "Browse i=85 returned no references.");
            browseTimes.Add(sw.Elapsed.TotalMilliseconds);
        }
        PrintStats("Browse i=85", browseTimes);

        foreach (var size in new[] { 10, 50, 100 })
        {
            var nodes = BuildRepeatedNodes(size);
            var samples = new List<double>();
            for (var i = 0; i < 100; i++)
            {
                var sw = Stopwatch.StartNew();
                var results = await persistent.ReadAsync(nodes)
                    ?? throw new InvalidOperationException($"Batch read x{size} returned null.");
                sw.Stop();
                Require(results.Length == size, $"Batch read x{size} returned an unexpected result count.");
                Require(results.All(r => r.StatusCode.IsGood), $"Batch read x{size} contained a bad status.");
                samples.Add(sw.Elapsed.TotalMilliseconds);
            }
            PrintStats($"BatchRead x{size}", samples);
        }

        var writeValues = BuildReadOnlyWrites(10);
        var writeTimes = new List<double>();
        for (var i = 0; i < 50; i++)
        {
            var sw = Stopwatch.StartNew();
            var results = await persistent.WriteAsync(writeValues)
                ?? throw new InvalidOperationException("Batch write returned null.");
            sw.Stop();
            Require(results.Length == 10, "Batch write returned an unexpected result count.");
            Require(results.All(r => r.StatusCode.IsBad), "Read-only batch write unexpectedly succeeded; no writable project tag should be used by this scenario.");
            writeTimes.Add(sw.Elapsed.TotalMilliseconds);
        }
        PrintStats("BatchWrite x10 (expected rejection)", writeTimes);

        await VerifyDemoChannelWritesAsync(persistent);
        await VerifyWaitBackpressureAsync(url);
        Console.WriteLine("None verification completed successfully.");
    }

    private static async Task VerifyDemoChannelWritesAsync(UaClient client)
    {
        Console.WriteLine();
        Console.WriteLine("DemoCH/Data writable-tag verification (read current values, then batch write them back)");

        var objectReferences = await BrowseChildrenAsync(client, "i=85");
        var demoChannel = objectReferences.FirstOrDefault(reference =>
            string.Equals(reference.BrowseName?.Name, "DemoCH", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reference.DisplayName?.Text, "DemoCH", StringComparison.OrdinalIgnoreCase));
        if (demoChannel == null)
        {
            var children = string.Join(", ", objectReferences.Select(reference => reference.BrowseName?.Name ?? reference.DisplayName?.Text ?? reference.NodeId.ToString()));
            throw new InvalidOperationException($"Could not find DemoCH below Objects. Found: {children}");
        }

        var dataFolder = (await BrowseChildrenAsync(client, demoChannel.NodeId)).FirstOrDefault(reference =>
            string.Equals(reference.BrowseName?.Name, "Data", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reference.DisplayName?.Text, "Data", StringComparison.OrdinalIgnoreCase));
        if (dataFolder == null)
            throw new InvalidOperationException($"Could not find Data below DemoCH ({demoChannel.NodeId}).");

        var variables = new List<ReferenceDescription>();
        await CollectVariablesAsync(client, dataFolder.NodeId, depth: 4, variables, limit: 100);
        Require(variables.Count > 0, "DemoCH/Data did not contain a variable node within four hierarchy levels.");

        var nodes = variables.Select(reference => (NodeId)reference.NodeId).ToArray();
        var readResults = await client.ReadAsync(nodes)
            ?? throw new InvalidOperationException("DemoCH/Data batch read returned null.");
        var accessResults = await client.ReadAsync(nodes, AttributeId.UserAccessLevel)
            ?? throw new InvalidOperationException("DemoCH/Data UserAccessLevel read returned null.");
        Require(accessResults.Length == readResults.Length, "DemoCH/Data UserAccessLevel read returned an unexpected result count.");

        var writableIndexes = Enumerable.Range(0, readResults.Length)
            .Where(index => readResults[index].StatusCode.IsGood &&
                            readResults[index].DataValue?.Value != null &&
                            accessResults[index].StatusCode.IsGood &&
                            HasWriteAccess(accessResults[index]))
            .Take(10)
            .ToArray();
        var writableValues = writableIndexes
            .Select(index => new WriteValue
            {
                NodeId = readResults[index].NodeId,
                Value = new DataValue(readResults[index].DataValue!.Value)
            })
            .ToArray();
        Require(writableValues.Length > 0, "DemoCH/Data variables did not yield a value with UserAccessLevel.CurrentWrite.");

        var sw = Stopwatch.StartNew();
        var probeResults = await client.WriteAsync(writableValues)
            ?? throw new InvalidOperationException("DemoCH/Data batch write returned null.");
        sw.Stop();
        var probeElapsed = sw.Elapsed.TotalMilliseconds;
        Require(probeResults.Length == writableValues.Length, "DemoCH/Data batch write returned an unexpected result count.");
        var confirmedWritable = Enumerable.Range(0, probeResults.Length)
            .Where(index => probeResults[index].StatusCode.IsGood)
            .ToArray();
        Require(confirmedWritable.Length > 0, $"DemoCH/Data writeability probe had no successful write: {string.Join(", ", probeResults.Select(result => result.StatusCode.GetStatusText()))}");

        var verifiedValues = confirmedWritable.Select(index => writableValues[index]).ToArray();
        var verifiedResults = await client.WriteAsync(verifiedValues)
            ?? throw new InvalidOperationException("Verified DemoCH/Data batch write returned null.");
        Require(verifiedResults.Length == verifiedValues.Length, "Verified DemoCH/Data batch write returned an unexpected result count.");
        Require(verifiedResults.All(result => result.StatusCode.IsGood), $"Verified DemoCH/Data batch write failed: {string.Join(", ", verifiedResults.Select(result => result.StatusCode.GetStatusText()))}");

        var successfulWriteTimes = new List<double>();
        for (var i = 0; i < 50; i++)
        {
            sw.Restart();
            var results = await client.WriteAsync(verifiedValues)
                ?? throw new InvalidOperationException("Timed DemoCH/Data batch write returned null.");
            sw.Stop();
            Require(results.Length == verifiedValues.Length && results.All(result => result.StatusCode.IsGood), "Timed DemoCH/Data batch write did not return all Good statuses.");
            successfulWriteTimes.Add(sw.Elapsed.TotalMilliseconds);
        }

        Console.WriteLine($"  DemoCH/Data node={dataFolder.NodeId}; discovered {variables.Count} variables, UserAccessLevel selected {writableValues.Length}");
        Console.WriteLine($"  Probe: {confirmedWritable.Length}/{writableValues.Length} accepted current values in {probeElapsed:F3} ms");
        Console.WriteLine($"  Probe details: {string.Join(", ", Enumerable.Range(0, probeResults.Length).Select(index => $"{variables[writableIndexes[index]].BrowseName?.Name ?? variables[writableIndexes[index]].NodeId.ToString()}={probeResults[index].StatusCode.GetStatusText()}"))}");
        Console.WriteLine($"  Verified batch write: {verifiedResults.Length}/{verifiedValues.Length} Good: {string.Join(", ", confirmedWritable.Select(index => variables[writableIndexes[index]].BrowseName?.Name ?? variables[writableIndexes[index]].NodeId.ToString()))}");
        PrintStats($"  DemoCH/Data BatchWrite x{verifiedValues.Length}", successfulWriteTimes);
    }

    private static async Task<List<ReferenceDescription>> BrowseChildrenAsync(UaClient client, NodeId nodeId)
    {
        var results = await client.BrowseAsync(nodeId, maxReferences: 1000)
            ?? throw new InvalidOperationException($"Browse {nodeId} returned null.");
        Require(results.Length == 1 && results[0].StatusCode.IsGood, $"Browse {nodeId} failed.");
        return results[0].References?.ToList() ?? new List<ReferenceDescription>();
    }

    private static async Task CollectVariablesAsync(UaClient client, NodeId nodeId, int depth, List<ReferenceDescription> variables, int limit)
    {
        if (depth < 0 || variables.Count >= limit)
            return;

        foreach (var child in await BrowseChildrenAsync(client, nodeId))
        {
            if (child.NodeClass == NodeClass.Variable)
            {
                variables.Add(child);
                if (variables.Count >= limit)
                    return;
            }
            else if (child.NodeClass == NodeClass.Object)
            {
                await CollectVariablesAsync(client, child.NodeId, depth - 1, variables, limit);
                if (variables.Count >= limit)
                    return;
            }
        }
    }

    private static async Task VerifyWaitBackpressureAsync(string url)
    {
        Console.WriteLine();
        Console.WriteLine("Subscription Wait-backpressure verification (i=2258, 250 ms publish interval, 1300 ms callback)");

        await using var client = new UaClient(url, new UaClientOptions
        {
            ApplicationName = "TinyUa-None-Backpressure",
            Timeout = 15000,
            MaxPublishRequests = 2,
            SubscriptionDispatch = new SubscriptionDispatchOptions
            {
                QueueCapacity = 2,
                OverflowPolicy = NotificationOverflowPolicy.Wait
            }
        });
        await client.RunAsync();

        var values = new ConcurrentQueue<DateTime>();
        var subscription = await client.SubscribeAsync<DateTime>("i=2258", value =>
        {
            values.Enqueue(value);
            Thread.Sleep(1300);
        }, interval: 250);

        var maxPending = 0;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(12);
        while (DateTime.UtcNow < deadline)
        {
            maxPending = Math.Max(maxPending, subscription.PendingNotificationMessages);
            await Task.Delay(100);
        }

        Require(values.Count >= 5, $"Received only {values.Count} data changes; expected at least 5.");
        Require(IsNonDecreasing(values), "Subscription callback values arrived out of order.");
        Require(subscription.DroppedNotificationMessages == 0, "Wait policy dropped a Publish response.");
        Console.WriteLine($"  callbacks={values.Count}, maxPending={maxPending}, dropped={subscription.DroppedNotificationMessages}");
        subscription.Dispose();
    }

    private static NodeId[] BuildRepeatedNodes(int count)
    {
        var nodes = new NodeId[count];
        for (var i = 0; i < count; i++)
            nodes[i] = ReadNodes[i % ReadNodes.Length];
        return nodes;
    }

    private static WriteValue[] BuildReadOnlyWrites(int count)
    {
        var values = new WriteValue[count];
        for (var i = 0; i < count; i++)
        {
            values[i] = new WriteValue
            {
                NodeId = ReadNodes[i % ReadNodes.Length],
                Value = new DataValue(new Variant(0))
            };
        }
        return values;
    }

    private static bool IsNonDecreasing(IEnumerable<DateTime> values)
    {
        var first = true;
        var previous = default(DateTime);
        foreach (var value in values)
        {
            if (!first && value < previous)
                return false;
            previous = value;
            first = false;
        }
        return true;
    }

    private static bool HasWriteAccess(ReadResult accessResult)
    {
        var accessLevel = accessResult.DataValue?.Value?.Value;
        if (accessLevel == null)
            return false;
        return (Convert.ToUInt32(accessLevel) & 0x02) != 0;
    }

    private static void PrintStats(string label, List<double> samples)
    {
        samples.Sort();
        var average = samples.Average();
        var p50 = samples[samples.Count / 2];
        var p99 = samples[(int)Math.Min(samples.Count - 1, Math.Ceiling(samples.Count * 0.99) - 1)];
        Console.WriteLine($"{label,-36} avg={average:F3}ms min={samples[0]:F3}ms p50={p50:F3}ms p99={p99:F3}ms max={samples[^1]:F3}ms n={samples.Count}");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
