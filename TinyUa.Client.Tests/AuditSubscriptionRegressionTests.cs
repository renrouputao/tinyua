using TinyUa.Client.Connection;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

public class AuditSubscriptionRegressionTests
{
    [Fact]
    public void KeepAliveDoesNotAdvanceOrAcknowledgeDataSequence()
    {
        using var sub = NewSubscription();
        sub.HandlePublishResponse(new PublishResponse
        {
            Parameters = new PublishResult { NotificationMessage = new NotificationMessage { SequenceNumber = 7 } }
        });
        Assert.Equal(0u, sub.LastSequenceNumber);
        Assert.Empty(sub.TakeAcknowledgements());
    }

    [Fact]
    public void AcknowledgementsRetainEverySequenceAndRetryOnlyRejectedOnes()
    {
        using var sub = NewSubscription();
        foreach (var seq in new uint[] { 1, 2, 3 }) sub.HandlePublishResponse(Data(seq));
        var sent = sub.TakeAcknowledgements();
        Assert.Equal(new uint[] { 1, 2, 3 }, sent.Order().ToArray());
        Assert.Empty(sub.TakeAcknowledgements());
        sub.CompleteAcknowledgement(1, true);
        sub.CompleteAcknowledgement(2, false);
        sub.CompleteAcknowledgement(3, true);
        Assert.Equal(new uint[] { 2 }, sub.TakeAcknowledgements());
        sub.ReleaseAcknowledgements();
        Assert.Equal(new uint[] { 2 }, sub.TakeAcknowledgements());
    }

    [Fact]
    public void SequenceWrapSkipsKeepAliveAndPreservesPendingAcks()
    {
        using var sub = NewSubscription();
        sub.HandlePublishResponse(Data(uint.MaxValue));
        sub.HandlePublishResponse(new PublishResponse { Parameters = new PublishResult { NotificationMessage = new NotificationMessage { SequenceNumber = 1 } } });
        Assert.Equal(uint.MaxValue, sub.LastSequenceNumber);
        sub.HandlePublishResponse(Data(1));
        Assert.Equal(1u, sub.LastSequenceNumber);
        Assert.Equal(new uint[] { 1, uint.MaxValue }, sub.TakeAcknowledgements().Order().ToArray());
    }

    [Fact]
    public async Task DisposedSubscriptionIsRemovedAndPendingCreationWaitCanBeCancelled()
    {
        var registry = new SubscriptionRegistry();
        using var disposed = NewSubscription();
        registry.Add(disposed);
        disposed.Dispose();
        Assert.Empty(registry.Snapshot());
        using var replacement = NewSubscription();
        var factory = new TaskCompletionSource<Subscription>(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = registry.GetOrCreateAsync(1000, () => factory.Task);
        using var cancel = new CancellationTokenSource();
        var second = registry.GetOrCreateAsync(1000, () => throw new Exception("Duplicate creator"), cancel.Token);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);
        factory.SetResult(replacement);
        Assert.Same(replacement, await first);
    }

    [Fact]
    public void ServiceErrorsDoNotTriggerConnectionRecovery()
    {
        Assert.False(UaClient.IsConnectionError(new UaException(0x801F0000, "BadUserAccessDenied")));
        Assert.False(UaClient.IsConnectionError(new UaException(0x80100000, "BadTooManyOperations")));
        Assert.True(UaClient.IsConnectionError(new UaException(0x80250000, "BadSessionIdInvalid")));
        Assert.True(UaClient.IsConnectionError(new IOException("Connection closed")));
    }

    [Fact]
    public void OptionsReturnedToCallerCannotChangeInternalSettings()
    {
        var options = new UaClientOptions { Security = new SecurityOptions { Policy = "None" } };
        var client = new UaClient(options);
        client.Options.Security.Policy = "Basic256Sha256";
        client.Options.SubscriptionDispatch.QueueCapacity = 999;
        Assert.Equal("None", client.Options.Security.Policy);
        Assert.NotEqual(999, client.Options.SubscriptionDispatch.QueueCapacity);
    }

    [Fact]
    public void BackoffJitterRemainsWithinConfiguredCap()
    {
        var policy = new BackoffPolicy(100, 1000, jitter: true);
        foreach (var expected in new[] { 100, 200, 400, 800, 1000, 1000 })
            Assert.InRange(policy.NextDelay(), (int)(expected * 0.8), expected);
    }

    private static Subscription NewSubscription() => new(null!, 1, 1000, 10, 5);
    private static PublishResponse Data(uint sequence) => new()
    {
        Parameters = new PublishResult
        {
            NotificationMessage = new NotificationMessage
            {
                SequenceNumber = sequence,
                NotificationData = new() { new ExtensionObject { TypeId = new NodeId(811u) } }
            }
        }
    };
}
