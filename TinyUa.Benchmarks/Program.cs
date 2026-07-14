using System.Diagnostics;
using TinyUa.Client;
using UaNodeId = TinyUa.Core.Types.NodeId;

namespace TinyUa.Benchmarks;

class Program
{
    const string DefaultUrl = "opc.tcp://localhost:49320";

    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Subcommand dispatch: security | latency | kepware | basic [url]
        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "basic";

        switch (cmd)
        {
            case "security":
                await SecurityBenchmarks.RunAsync();
                return;
            case "latency":
                await LatencyBenchmarks.RunAsync(args.Length > 1 ? args[1] : DefaultUrl);
                return;
            case "kepware":
                await KepwareTest.RunAsync(args.Length > 1 ? args[1] : DefaultUrl);
                return;
            case "basic":
            default:
                // Treat first arg as url when it isn't a known subcommand
                var url = args.Length > 0 && !IsKnownSubcommand(args[0]) ? args[0] : DefaultUrl;
                await RunBasicBenchmarkAsync(url);
                return;
        }
    }

    static bool IsKnownSubcommand(string s)
        => s.Equals("security", StringComparison.OrdinalIgnoreCase)
           || s.Equals("latency", StringComparison.OrdinalIgnoreCase)
           || s.Equals("kepware", StringComparison.OrdinalIgnoreCase)
           || s.Equals("basic", StringComparison.OrdinalIgnoreCase);

    // ═══════════════════════════════════════════════════════════════════════
    //  Basic benchmark: throughput-oriented (uses constructor-style API).
    //  Usage: dotnet run --project TinyUa.Benchmarks -- [url]
    //         dotnet run --project TinyUa.Benchmarks -- basic [url]
    // ═══════════════════════════════════════════════════════════════════════
    static async Task RunBasicBenchmarkAsync(string url)
    {
        Console.WriteLine("TinyUa Basic Benchmark");
        Console.WriteLine($"Server: {url}");
        Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
        Console.WriteLine();

        Console.WriteLine("--- TinyUa ---");
        var ua = await RunTinyUaAsync(url);
        Console.WriteLine();

        Console.WriteLine("=== RESULTS ===");
        Console.WriteLine($"  Batch Read (100x50):  {ua.BatchRead} us/batch");
        Console.WriteLine($"  Batch Write (x200):   {ua.BatchWrite} us/op");
        Console.WriteLine($"  Browse (x100):        {ua.Browse} us/op");
        Console.WriteLine($"  Subscription (10s):   {ua.SubNotifs} notifs");
        Console.WriteLine($"  Connect+Disc (x5):    {ua.ConnDiscMs} ms avg");
        Console.WriteLine();

        Console.WriteLine("  Read Scaling:");
        Console.WriteLine($"  {"Size",5} {"TinyUa",8}");
        Console.WriteLine($"  {"-----",5} {"------",8}");
        foreach (var kv in ua.ReadSizes.OrderBy(x => x.Key))
            Console.WriteLine($"  {kv.Key,5} {kv.Value,7}us");

        Console.WriteLine();
        Console.WriteLine("Done.");
    }

    static async Task<Results> RunTinyUaAsync(string url)
    {
        var r = new Results();
        await using var client = new UaClient(url, new UaClientOptions
        {
            ApplicationName = "TinyUa-Bench",
            Timeout = 15000
        });
        await client.RunAsync();

        r.BatchRead = await BenchReadAsync(client, 100, 50);
        r.BatchWrite = await BenchWriteAsync(client);
        r.Browse = await BenchBrowseAsync(client);

        r.ConnDiscMs = await BenchConnectDisconnectAsync(url);
        r.SubNotifs = await BenchSubscribeAsync(client);

        Console.WriteLine($"  Batch Read (100x50):  {r.BatchRead} us/batch");
        Console.WriteLine($"  Batch Write (x200):   {r.BatchWrite} us/op");
        Console.WriteLine($"  Browse (x100):        {r.Browse} us/op");
        Console.WriteLine($"  Subscription (10s):   {r.SubNotifs} notifs");
        Console.WriteLine($"  Connect+Disc (x5):    {r.ConnDiscMs} ms avg");

        Console.WriteLine("  Read Scaling:");
        foreach (var size in new[] { 3, 10, 20, 50, 100 })
        {
            var val = await BenchReadAsync(client, size, 100);
            r.ReadSizes[size] = val;
            Console.WriteLine($"    {size,4} nodes: {val,7} us");
        }

        return r;
    }

    static async Task<long> BenchReadAsync(UaClient client, int nodeCount, int repeat)
    {
        var nodes = BuildNodeArray(nodeCount);
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < repeat; i++) await client.ReadAsync(nodes);
        sw.Stop();
        return sw.Elapsed.ToMicroseconds() / repeat;
    }

    static async Task<long> BenchWriteAsync(UaClient client)
    {
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 200; i++)
            try { await client.WriteAsync(new UaNodeId("ns=2;s=Demo.SimulationSpeed"), 50); } catch { }
        sw.Stop();
        return sw.Elapsed.ToMicroseconds() / 200;
    }

    static async Task<long> BenchBrowseAsync(UaClient client)
    {
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 100; i++) await client.BrowseAsync(new UaNodeId(84, 0));
        sw.Stop();
        return sw.Elapsed.ToMicroseconds() / 100;
    }

    static async Task<long> BenchSubscribeAsync(UaClient client)
    {
        var count = 0;
        var sub = await client.SubscribeAsync<DateTime>("i=2258", _ => Interlocked.Increment(ref count), interval: 250);
        await Task.Delay(10000);
        sub.Dispose();
        return count;
    }

    static async Task<long> BenchConnectDisconnectAsync(string url)
    {
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 5; i++)
        {
            var c = new UaClient(url, new UaClientOptions { Timeout = 10000 });
            await c.RunAsync();
            await c.DisposeAsync();
        }
        sw.Stop();
        return sw.ElapsedMilliseconds / 5;
    }

    static UaNodeId[] BuildNodeArray(int count)
    {
        uint[] ids = [2256, 2258, 2259, 2254, 2255, 2267, 2257, 2994, 12885];
        var nodes = new UaNodeId[count];
        for (int i = 0; i < count; i++) nodes[i] = new UaNodeId(ids[i % ids.Length], 0);
        return nodes;
    }

    class Results
    {
        public long BatchRead;
        public long BatchWrite;
        public long Browse;
        public long SubNotifs;
        public long ConnDiscMs;
        public Dictionary<int, long> ReadSizes = new();
    }
}

static class TimeSpanExt
{
    public static long ToMicroseconds(this TimeSpan ts) => (long)(ts.TotalMilliseconds * 1000);
}
