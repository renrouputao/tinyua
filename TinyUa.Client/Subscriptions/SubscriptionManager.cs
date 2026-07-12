using TinyUa.Core;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;
using TinyUa.Client.Connection;
using TinyUa.Client.Services;

namespace TinyUa.Client.Subscriptions
{
    /// <summary>
    /// Callback for data change notifications. Receives the source <see cref="NodeId"/>, the new value, and the quality status.
    /// </summary>
    /// <param name="nodeId">The NodeId of the monitored item that changed.</param>
    /// <param name="value">The new value, or null.</param>
    /// <param name="status">The quality status code.</param>
    public delegate void DataChangeHandler(NodeId nodeId, object? value, StatusCode status);

    /// <summary>
    /// Extended data change callback. Carries the same (nodeId, value, status) as
    /// <see cref="DataChangeHandler"/> plus the source and server timestamps from the notification.
    /// The timestamps are nullable — they are absent when the server does not return them.
    /// </summary>
    /// <param name="nodeId">The NodeId of the monitored item that changed.</param>
    /// <param name="value">The new value, or null.</param>
    /// <param name="status">The quality status code (always available, even when the value is null).</param>
    /// <param name="sourceTimestamp">The source timestamp, or null if not provided.</param>
    /// <param name="serverTimestamp">The server timestamp, or null if not provided.</param>
    public delegate void DataChangeHandlerEx(NodeId nodeId, object? value, StatusCode status,
        DateTime? sourceTimestamp, DateTime? serverTimestamp);

    internal static class SubscriptionManager
    {
        internal static async Task<Subscription> CreateSubscriptionAsync(SubscriptionRouter router, double publishingInterval = 1000.0, bool autoStart = true, int maxPublishRequests = 2, ILogger? logger = null)
        {
            var result = await router.CreateSubscriptionAsync(publishingInterval).ConfigureAwait(false);
            var subscription = new Subscription(
                router,
                result.SubscriptionId,
                result.RevisedPublishingInterval,
                result.RevisedLifetimeCount,
                result.RevisedMaxKeepAliveCount,
                maxPublishRequests,
                logger);

            if (autoStart)
                subscription.StartPublishing();

            return subscription;
        }
    }

    /// <summary>
    /// Represents a single item being monitored within a subscription.
    /// Tracks the item's identifier, node, sampling configuration, and the latest received value.
    /// </summary>
    public class MonitoredItem
    {
        internal uint MonitoredItemId { get; set; }
        internal uint ClientHandle { get; set; }
        internal NodeId NodeId { get; set; } = new NodeId();
        internal double SamplingInterval { get; set; }
        internal object? LastValue { get; set; }
        internal StatusCode LastStatus { get; set; } = new StatusCode();
        internal DataChangeHandler? OnDataChange { get; set; }
        internal DataChangeHandlerEx? OnDataChangeEx { get; set; }
    }

    /// <summary>
    /// Represents an OPC UA subscription: a collection of monitored items plus the dispatch of
    /// their data change notifications. Publish requests are pumped by the session-level
    /// <see cref="PublishEngine"/>; StartPublishing/StopPublishing attach and detach this
    /// subscription from that engine. Call <see cref="Dispose"/> to release resources.
    /// </summary>
    public class Subscription : IDisposable
    {
        private readonly SubscriptionRouter _router;
        private readonly ILogger? _logger;
        private readonly object _lock = new();
        private readonly int _maxPublishRequests;
        private int _isDisposed;
        internal volatile bool _running;
        private volatile uint _lastSequenceNumber;
        private int _publishCount;
        private int _notificationCount;

        internal uint SubscriptionId { get; }
        internal double PublishingInterval { get; }
        internal uint LifetimeCount { get; }
        internal uint MaxKeepAliveCount { get; }
        internal Dictionary<uint, MonitoredItem> MonitoredItems { get; } = new();
        private int _nextClientHandle = 0;

        internal event Action<NodeId, object?, StatusCode>? OnDataChange;

        internal event Action? OnKeepAlive;

        internal event Action<Exception>? OnPublishError;

        internal int PublishCount => _publishCount;
        internal int NotificationCount => _notificationCount;
        internal uint LastSequenceNumber => _lastSequenceNumber;

        internal bool IsPublishing => _running;
        internal bool IsSubscriptionDisposed => Volatile.Read(ref _isDisposed) != 0;

        internal Subscription(SubscriptionRouter router, uint subscriptionId,
            double publishingInterval, uint lifetimeCount, uint maxKeepAliveCount,
            int maxPublishRequests = 2, ILogger? logger = null)
        {
            _router = router;
            _logger = logger;
            SubscriptionId = subscriptionId;
            PublishingInterval = publishingInterval;
            LifetimeCount = lifetimeCount;
            MaxKeepAliveCount = maxKeepAliveCount;
            _maxPublishRequests = Math.Max(1, maxPublishRequests);
            _running = false;
            _lastSequenceNumber = 0;

            _router?.Register(subscriptionId, this);
        }

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, DataChangeHandler? handler = null, uint queueSize = 0)
        {
            return await AddMonitoredItemAsync(nodeId, PublishingInterval, handler, queueSize).ConfigureAwait(false);
        }

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, double samplingInterval, DataChangeHandler? handler = null, uint queueSize = 0, DataChangeHandlerEx? handlerEx = null)
        {
            var clientHandle = (uint)Interlocked.Increment(ref _nextClientHandle);
            var results = await _router.CreateMonitoredItemsAsync(SubscriptionId, new[] { nodeId }, AttributeId.Value, samplingInterval, new[] { clientHandle }, queueSize).ConfigureAwait(false);

            if (results == null || results.Length == 0)
                throw new InvalidOperationException("Failed to create monitored item");

            var result = results[0];
            result.StatusCode.Check();

            var item = new MonitoredItem
            {
                MonitoredItemId = result.MonitoredItemId,
                ClientHandle = clientHandle,
                NodeId = nodeId,
                SamplingInterval = samplingInterval
            };

            if (handler != null)
                item.OnDataChange = handler;
            if (handlerEx != null)
                item.OnDataChangeEx = handlerEx;

            lock (_lock)
                MonitoredItems[clientHandle] = item;

            return item;
        }

        internal async Task AddMonitoredItemsAsync(NodeId[] nodeIds, DataChangeHandler? handler = null, uint queueSize = 0)
        {
            var clientHandles = new uint[nodeIds.Length];
            for (int i = 0; i < nodeIds.Length; i++)
                clientHandles[i] = (uint)Interlocked.Increment(ref _nextClientHandle);

            var results = await _router.CreateMonitoredItemsAsync(SubscriptionId, nodeIds, AttributeId.Value, PublishingInterval, clientHandles, queueSize).ConfigureAwait(false);

            if (results == null)
                throw new InvalidOperationException("Failed to create monitored items");

            for (int i = 0; i < results.Length; i++)
            {
                var result = results[i];
                result.StatusCode.Check();

                var item = new MonitoredItem
                {
                    MonitoredItemId = result.MonitoredItemId,
                    ClientHandle = clientHandles[i],
                    NodeId = nodeIds[i]
                };

                if (handler != null)
                    item.OnDataChange = handler;

                lock (_lock)
                    MonitoredItems[clientHandles[i]] = item;
            }
        }

        /// <summary>Attaches this subscription to the session publish engine. Idempotent.</summary>
        internal void StartPublishing()
        {
            lock (_lock)
            {
                if (Volatile.Read(ref _isDisposed) != 0) return;
                if (_running) return;
                _running = true;
            }
            _router?.Engine.Attach(this, _maxPublishRequests);
        }

        /// <summary>Detaches this subscription from the session publish engine. Idempotent.</summary>
        internal void StopPublishing()
        {
            lock (_lock)
            {
                if (!_running) return;
                _running = false;
            }
            _router?.Engine.Detach(this);
        }

        /// <summary>
        /// Handles a decoded PublishResponse addressed to this subscription: updates the sequence
        /// number, dispatches notifications or the keep-alive event, and surfaces processing
        /// errors via <see cref="OnPublishError"/>.
        /// </summary>
        internal void HandlePublishResponse(PublishResponse response)
        {
            Interlocked.Increment(ref _publishCount);
            try
            {
                response.ResponseHeader.ServiceResult.Check();

                var notificationMsg = response.Parameters.NotificationMessage;
                _lastSequenceNumber = notificationMsg.SequenceNumber;

                if (notificationMsg.NotificationData.Count > 0)
                {
                    ProcessNotification(notificationMsg);
                }
                else
                {
                    _logger?.LogDebug($"Subscription {SubscriptionId}: keep-alive (seq={_lastSequenceNumber})");
                    OnKeepAlive?.Invoke();
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: error processing PublishResponse");
                OnPublishError?.Invoke(ex);
            }
        }

        internal void ProcessNotification(NotificationMessage message)
        {
            foreach (var data in message.NotificationData)
            {
                if (data.Body == null || data.Body.Length == 0) continue;

                var decoder = new BinaryDecoder(data.Body);
                var dataChange = DataChangeNotificationData.Decode(decoder);

                foreach (var item in dataChange.Notifications)
                {
                    Interlocked.Increment(ref _notificationCount);
                    var status = item.Value?.StatusCode ?? new StatusCode();
                    ProcessDataChange(item.ClientHandle, item.Value, status);
                }
            }
        }

        private void ProcessDataChange(uint clientHandle, DataValue? value, StatusCode status)
        {

            MonitoredItem? item;
            object? capturedValue;
            StatusCode capturedStatus;
            DateTime? capturedSourceTs;
            DateTime? capturedServerTs;

            lock (_lock)
            {
                if (!MonitoredItems.TryGetValue(clientHandle, out item))
                    return;
                capturedValue = value?.Value?.Value;
                capturedStatus = value?.StatusCode ?? new StatusCode();
                capturedSourceTs = value?.SourceTimestamp;
                capturedServerTs = value?.ServerTimestamp;
                item.LastValue = capturedValue;
                item.LastStatus = capturedStatus;
            }

            try { item.OnDataChange?.Invoke(item.NodeId, capturedValue, capturedStatus); }
            catch (Exception ex) { _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: OnDataChange handler threw"); }

            try { item.OnDataChangeEx?.Invoke(item.NodeId, capturedValue, capturedStatus, capturedSourceTs, capturedServerTs); }
            catch (Exception ex) { _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: OnDataChangeEx handler threw"); }

            try { OnDataChange?.Invoke(item.NodeId, capturedValue, capturedStatus); }
            catch (Exception ex) { _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: OnDataChange event handler threw"); }
        }

        internal async Task<StatusCode[]> DeleteMonitoredItemsAsync(uint[] monitoredItemIds)
        {
            if (monitoredItemIds == null || monitoredItemIds.Length == 0)
                return Array.Empty<StatusCode>();

            var results = await _router.DeleteMonitoredItemsAsync(SubscriptionId, monitoredItemIds).ConfigureAwait(false);

            lock (_lock)
            {
                var idsToRemove = new HashSet<uint>(monitoredItemIds);
                var handlesToRemove = MonitoredItems
                    .Where(kvp => idsToRemove.Contains(kvp.Value.MonitoredItemId))
                    .Select(kvp => kvp.Key)
                    .ToList();
                foreach (var handle in handlesToRemove)
                    MonitoredItems.Remove(handle);
            }

            return results;
        }

        internal async Task DeleteAsync()
        {
            StopPublishing();

            _router?.Unregister(SubscriptionId);

            try
            {
                await _router.DeleteSubscriptionsAsync(new[] { SubscriptionId }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, $"Subscription {SubscriptionId}: DeleteSubscriptions error (ignored)");
            }
        }

        /// <summary>
        /// Stops publishing and releases all resources held by this subscription.
        /// Safe to call multiple times; subsequent calls have no effect.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

            StopPublishing();

            _router?.Unregister(SubscriptionId);
        }
    }
}
