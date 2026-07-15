using System.Collections.Concurrent;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;

namespace TinyUa.Client.Tests;

public class SubscriptionDispatchTests
{
    [Fact]
    public void Options_Clone_CopiesSubscriptionDispatch()
    {
        var source = new UaClientOptions
        {
            SubscriptionDispatch = new SubscriptionDispatchOptions
            {
                QueueCapacity = 7,
                OverflowPolicy = NotificationOverflowPolicy.DropOldest
            }
        };

        var clone = source.Clone();
        source.SubscriptionDispatch.QueueCapacity = 3;

        Assert.Equal(7, clone.SubscriptionDispatch.QueueCapacity);
        Assert.Equal(NotificationOverflowPolicy.DropOldest, clone.SubscriptionDispatch.OverflowPolicy);
    }

    [Fact]
    public async Task WaitPolicy_BoundsTheQueue_AndPreservesCallbackOrder()
    {
        using var callbackEntered = new ManualResetEventSlim();
        using var releaseCallback = new ManualResetEventSlim();
        var observed = new ConcurrentQueue<uint>();
        var subscription = CreateSubscription(NotificationOverflowPolicy.Wait);

        try
        {
            subscription.OnKeepAlive += () =>
            {
                observed.Enqueue(subscription.LastSequenceNumber);
                callbackEntered.Set();
                releaseCallback.Wait(TimeSpan.FromSeconds(5));
            };

            await subscription.EnqueuePublishResponseAsync(CreateKeepAlive(1));
            Assert.True(callbackEntered.Wait(TimeSpan.FromSeconds(2)));

            await subscription.EnqueuePublishResponseAsync(CreateKeepAlive(2));
            var thirdEnqueue = subscription.EnqueuePublishResponseAsync(CreateKeepAlive(3));

            await Task.Delay(100);
            Assert.False(thirdEnqueue.IsCompleted);
            Assert.Equal(1, subscription.PendingNotificationMessages);

            releaseCallback.Set();
            await thirdEnqueue.WaitAsync(TimeSpan.FromSeconds(2));
            await WaitUntilAsync(() => observed.Count == 3);

            Assert.Equal(new uint[] { 1, 2, 3 }, observed);
            Assert.Equal(0, subscription.DroppedNotificationMessages);
        }
        finally
        {
            releaseCallback.Set();
            subscription.Dispose();
        }
    }

    [Fact]
    public async Task DropNewest_AcknowledgesDroppedSequence_WithoutRegressing()
    {
        using var callbackEntered = new ManualResetEventSlim();
        using var releaseCallback = new ManualResetEventSlim();
        var subscription = CreateSubscription(NotificationOverflowPolicy.DropNewest);

        try
        {
            subscription.OnKeepAlive += () =>
            {
                callbackEntered.Set();
                releaseCallback.Wait(TimeSpan.FromSeconds(5));
            };

            await subscription.EnqueuePublishResponseAsync(CreateKeepAlive(1));
            Assert.True(callbackEntered.Wait(TimeSpan.FromSeconds(2)));
            await subscription.EnqueuePublishResponseAsync(CreateKeepAlive(2));
            await subscription.EnqueuePublishResponseAsync(CreateKeepAlive(3));

            Assert.Equal(1, subscription.DroppedNotificationMessages);
            Assert.Equal(3u, subscription.LastSequenceNumber);

            releaseCallback.Set();
            await WaitUntilAsync(() => subscription.PendingNotificationMessages == 0);
            Assert.Equal(3u, subscription.LastSequenceNumber);
        }
        finally
        {
            releaseCallback.Set();
            subscription.Dispose();
        }
    }

    private static Subscription CreateSubscription(NotificationOverflowPolicy overflowPolicy) => new(
        router: null!,
        subscriptionId: 1,
        publishingInterval: 1000,
        lifetimeCount: 10,
        maxKeepAliveCount: 5,
        dispatchOptions: new SubscriptionDispatchOptions
        {
            QueueCapacity = 1,
            OverflowPolicy = overflowPolicy
        });

    private static PublishResponse CreateKeepAlive(uint sequenceNumber) => new()
    {
        Parameters = new PublishResult
        {
            SubscriptionId = 1,
            NotificationMessage = new NotificationMessage { SequenceNumber = sequenceNumber }
        }
    };

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (!predicate())
        {
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException("Condition was not met within 2 seconds.");
            await Task.Delay(10);
        }
    }
}
