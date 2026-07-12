using System.Reflection;
using TinyUa.Client.Connection;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

/// <summary>
/// Tests for the extended data-change callback (<see cref="DataChangeHandlerEx"/>) that carries
/// source/server timestamps in addition to the standard (nodeId, value, status). The timestamps
/// are already decoded on the notification's DataValue but were previously discarded.
/// </summary>
public class DataChangeHandlerExTests
{
    private static Subscription CreateTestSubscription()
    {
        var conn = new UaConnection(1000, NullLogger.Instance);
        var router = new SubscriptionRouter(conn);
        return new Subscription(router, subscriptionId: 1, publishingInterval: 1000.0,
            lifetimeCount: 10, maxKeepAliveCount: 5, maxPublishRequests: 2, logger: NullLogger.Instance);
    }

    private static MethodInfo ProcessDataChange =>
        typeof(Subscription).GetMethod("ProcessDataChange", BindingFlags.NonPublic | BindingFlags.Instance)
        ?? throw new InvalidOperationException("ProcessDataChange not found");

    [Fact]
    public void ExtendedCallback_ReceivesValueStatusAndTimestamps()
    {
        var sub = CreateTestSubscription();
        try
        {
            var source = new DateTime(2026, 7, 12, 1, 2, 3, DateTimeKind.Utc);
            var server = new DateTime(2026, 7, 12, 1, 2, 4, DateTimeKind.Utc);

            NodeId? gotNode = null;
            object? gotValue = null;
            StatusCode gotStatus = default;
            DateTime? gotSource = null;
            DateTime? gotServer = null;
            int calls = 0;

            var item = new MonitoredItem
            {
                ClientHandle = 7u,
                NodeId = new NodeId(2258, 0),
                OnDataChangeEx = (n, v, s, src, srv) =>
                {
                    gotNode = n; gotValue = v; gotStatus = s; gotSource = src; gotServer = srv;
                    calls++;
                }
            };
            sub.MonitoredItems[7u] = item;

            var dv = new DataValue(new Variant(42.5d, VariantType.Double), StatusCode.Good)
            {
                SourceTimestamp = source,
                ServerTimestamp = server
            };

            ProcessDataChange.Invoke(sub, new object?[] { 7u, dv, StatusCode.Good });

            Assert.Equal(1, calls);
            Assert.Equal(new NodeId(2258, 0), gotNode);
            Assert.Equal(42.5d, gotValue);
            Assert.True(gotStatus.IsGood);
            Assert.Equal(source, gotSource);
            Assert.Equal(server, gotServer);
        }
        finally { sub.Dispose(); }
    }

    [Fact]
    public void ExtendedCallback_NullDataValue_StillDeliversStatus_TimestampsNull()
    {
        var sub = CreateTestSubscription();
        try
        {
            StatusCode gotStatus = new StatusCode(0x12345678); // sentinel to prove it was overwritten
            DateTime? gotSource = new DateTime(1999, 1, 1);
            DateTime? gotServer = new DateTime(1999, 1, 1);
            bool called = false;

            var item = new MonitoredItem
            {
                ClientHandle = 9u,
                NodeId = new NodeId(1, 0),
                OnDataChangeEx = (n, v, s, src, srv) =>
                {
                    gotStatus = s; gotSource = src; gotServer = srv; called = true;
                }
            };
            sub.MonitoredItems[9u] = item;

            // value == null: status must still be delivered (default Good), timestamps null.
            ProcessDataChange.Invoke(sub, new object?[] { 9u, null, new StatusCode() });

            Assert.True(called);
            Assert.True(gotStatus.IsGood);   // default StatusCode() is Good, not the sentinel
            Assert.Null(gotSource);
            Assert.Null(gotServer);
        }
        finally { sub.Dispose(); }
    }

    [Fact]
    public void StandardAndExtendedCallbacks_BothFire()
    {
        var sub = CreateTestSubscription();
        try
        {
            bool std = false, ext = false;
            var item = new MonitoredItem
            {
                ClientHandle = 5u,
                NodeId = new NodeId(3, 0),
                OnDataChange = (n, v, s) => std = true,
                OnDataChangeEx = (n, v, s, src, srv) => ext = true
            };
            sub.MonitoredItems[5u] = item;

            var dv = new DataValue(new Variant(1, VariantType.Int32), StatusCode.Good);
            ProcessDataChange.Invoke(sub, new object?[] { 5u, dv, StatusCode.Good });

            Assert.True(std);
            Assert.True(ext);
        }
        finally { sub.Dispose(); }
    }
}
