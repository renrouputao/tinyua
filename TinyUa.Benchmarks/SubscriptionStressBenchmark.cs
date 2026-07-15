using TinyUa.Client;
using TinyUa.Client.Subscriptions;

namespace TinyUa.Benchmarks;

/// <summary>
/// Live subscription stress scenario that does not modify server data. It uses the standard
/// ServerStatus.CurrentTime node to exercise fast callback throughput and bounded slow-callback
/// backpressure independently.
/// Usage: dotnet run --project TinyUa.Benchmarks -- substress [url]
/// </summary>
internal static class SubscriptionStressBenchmark
{
    private const string CurrentTimeNode = "i=2258";

    public static async Task RunAsync(string url)
    {
        Console.WriteLine("TinyUa Subscription Stress Test (None)");
        Console.WriteLine($"Server: {url}");
        Console.WriteLine("Data source: ServerStatus.CurrentTime; no server values are written.");
        Console.WriteLine();

        await using var client = new UaClient(url, new UaClientOptions
        {
            ApplicationName = "TinyUa-Subscription-Stress",
            Timeout = 15000,
            MaxPublishRequests = 2,
            SubscriptionDispatch = new SubscriptionDispatchOptions
            {
                QueueCapacity = 2,
                OverflowPolicy = NotificationOverflowPolicy.Wait
            }
        });
        await client.RunAsync();

        await RunFastCallbackScenarioAsync(client);
        await RunSlowCallbackScenarioAsync(client);

        Console.WriteLine("Subscription stress test completed successfully.");
    }

    private static async Task RunFastCallbackScenarioAsync(UaClient client)
    {
        const int monitoredItems = 64;
        var callbackCount = 0;
        Subscription? subscription = null;

        try
        {
            for (var i = 0; i < monitoredItems; i++)
            {
                subscription = await client.SubscribeAsync<DateTime>(CurrentTimeNode, _ =>
                {
                    Interlocked.Increment(ref callbackCount);
                }, interval: 250);
            }

            await Task.Delay(TimeSpan.FromSeconds(6));

            var activeSubscription = subscription
                ?? throw new InvalidOperationException("Fast callback subscription was not created.");
            Require(callbackCount >= monitoredItems * 3,
                $"Fast callback scenario received only {callbackCount} notifications; expected at least {monitoredItems * 3}.");
            Require(activeSubscription.DroppedNotificationMessages == 0,
                "Fast callback scenario dropped a Publish response.");

            Console.WriteLine($"Fast callbacks: monitoredItems={monitoredItems}, callbacks={callbackCount}, pending={activeSubscription.PendingNotificationMessages}, dropped={activeSubscription.DroppedNotificationMessages}");
        }
        finally
        {
            subscription?.Dispose();
        }
    }

    private static async Task RunSlowCallbackScenarioAsync(UaClient client)
    {
        const int subscriptionCount = 3;
        var subscriptions = new Subscription[subscriptionCount];
        var callbackCounts = new int[subscriptionCount];
        var maxPending = new int[subscriptionCount];

        try
        {
            for (var i = 0; i < subscriptionCount; i++)
            {
                var capturedIndex = i;
                subscriptions[i] = await client.SubscribeAsync<DateTime>(CurrentTimeNode, _ =>
                {
                    Interlocked.Increment(ref callbackCounts[capturedIndex]);
                    Thread.Sleep(1300);
                }, interval: 300 + i);
            }

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(12);
            while (DateTime.UtcNow < deadline)
            {
                for (var i = 0; i < subscriptionCount; i++)
                    maxPending[i] = Math.Max(maxPending[i], subscriptions[i].PendingNotificationMessages);
                await Task.Delay(100);
            }

            Require(callbackCounts.All(count => count >= 3),
                $"Slow callback scenario did not make progress for every subscription: {string.Join(", ", callbackCounts)}.");
            Require(maxPending.Any(count => count == 2),
                $"Slow callback scenario did not fill a queue: {string.Join(", ", maxPending)}.");
            Require(subscriptions.All(subscription => subscription.DroppedNotificationMessages == 0),
                "Wait policy dropped a Publish response under slow callback pressure.");

            Console.WriteLine($"Slow callbacks: counts=[{string.Join(", ", callbackCounts)}], maxPending=[{string.Join(", ", maxPending)}], dropped=[{string.Join(", ", subscriptions.Select(subscription => subscription.DroppedNotificationMessages))}]");
        }
        finally
        {
            foreach (var subscription in subscriptions)
                subscription?.Dispose();
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
