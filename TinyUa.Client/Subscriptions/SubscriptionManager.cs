using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;
using TinyUa.Core.Client.Connection;
using TinyUa.Core.Client.Services;

namespace TinyUa.Core.Client.Subscriptions
{
    /// <summary>
    /// Callback for data change notifications. Receives the source <see cref="NodeId"/>, the new value, and the quality status.
    /// </summary>
    /// <param name="nodeId">The NodeId of the monitored item that changed.</param>
    /// <param name="value">The new value, or null.</param>
    /// <param name="status">The quality status code.</param>
    public delegate void DataChangeHandler(NodeId nodeId, object? value, StatusCode status);

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
    }

    /// <summary>
    /// Represents an OPC UA subscription that manages a publish loop and a collection of monitored items.
    /// Maintains credits, sequence numbers, and forwards notifications to registered handlers.
    /// Call <see cref="Dispose"/> to stop publishing and release resources.
    /// </summary>
    public class Subscription : IDisposable
    {
        private readonly SubscriptionRouter _router;
        private readonly ILogger? _logger;
        private readonly CancellationTokenSource _cts = new();
        private readonly object _lock = new();
        private int _isDisposed;
        internal volatile bool _running;
        private Task? _publishTask;
        private int _credits;
        private int _maxCredits;
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

        internal bool IsPublishing => Volatile.Read(ref _publishTask) != null;
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
            _maxCredits = Math.Max(1, maxPublishRequests);
            _running = false;
            _credits = 0;
            _lastSequenceNumber = 0;

            _router?.Register(subscriptionId, this);
        }

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, DataChangeHandler? handler = null, uint queueSize = 0)
        {
            return await AddMonitoredItemAsync(nodeId, PublishingInterval, handler, queueSize).ConfigureAwait(false);
        }

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, double samplingInterval, DataChangeHandler? handler = null, uint queueSize = 0)
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

        internal void StartPublishing()
        {
            lock (_lock)
            {
                if (Volatile.Read(ref _isDisposed) != 0) return;
                if (_publishTask != null)
                    return;

                _running = true;
                _publishTask = Task.Run(() => PublishLoopAsync(_cts.Token), _cts.Token);
            }
        }

        private async Task PublishLoopAsync(CancellationToken ct)
        {

            var shutdownSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            ct.Register(() => shutdownSignal.TrySetResult(true));

            try
            {

                _logger?.LogDebug($"Subscription {SubscriptionId}: filling credit pool ({_maxCredits} credits)");
                for (int i = 0; i < _maxCredits; i++)
                {
                    if (!_running) break;
                    Interlocked.Increment(ref _credits);
                    SendOnePublishAsync().Forget(_logger ?? NullLogger.Instance, "SendOnePublishAsync(credit fill)");
                }
                _logger?.LogDebug($"Subscription {SubscriptionId}: credit pool filled ({_credits} in flight)");

                while (_running && !ct.IsCancellationRequested)
                {
                    try
                    {

                        var completed = await shutdownSignal.Task.WaitAsync(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                        if (completed) break;
                    }
                    catch (OperationCanceledException) { break; }
                    catch (TimeoutException) { }

                    if (!_running || ct.IsCancellationRequested) break;

                    var currentCredits = Volatile.Read(ref _credits);
                    if (currentCredits <= 0)
                    {
                        _logger?.LogDebug($"Subscription {SubscriptionId}: credit pool empty, fallback refill");
                        for (int i = 0; i < _maxCredits; i++)
                        {
                            if (!_running) break;
                            Interlocked.Increment(ref _credits);
                            _ = SendOnePublishAsync();
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: publish loop unexpected error");
            }
            finally
            {
                _logger?.LogDebug($"Subscription {SubscriptionId}: publish loop stopped (notifs={_notificationCount}, publishes={_publishCount})");
            }
        }

        private async Task SendOnePublishAsync()
        {
            if (!_running) return;
            try
            {
                uint seq = _lastSequenceNumber;
                await _router.SendPublishWithCallbackAsync(SubscriptionId, seq, body => OnPublishResponse(body)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, $"Subscription {SubscriptionId}: SendOnePublish failed");
            }
        }

        private void OnPublishResponse(byte[] body)
        {

            Interlocked.Decrement(ref _credits);
            Interlocked.Increment(ref _publishCount);

            try
            {
                var decoder = new BinaryDecoder(body);
                var response = PublishResponse.Decode(decoder);

                if (response.Parameters.SubscriptionId != this.SubscriptionId)
                {
                    Subscription? target = null;
                    _router?.TryGet(response.Parameters.SubscriptionId, out target);

                    if (target != null && target._running)
                    {

                        target.OnPublishResponseForwarded(body);
                    }
                    else
                    {
                        _logger?.LogDebug($"Subscription {SubscriptionId}: PublishResponse for unknown/stopped sub {response.Parameters.SubscriptionId}");
                    }
                }
                else
                {
                    ProcessOwnPublishResponse(response);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: error processing PublishResponse");
                OnPublishError?.Invoke(ex);
            }

            if (_running)
            {
                int needed = _maxCredits - Volatile.Read(ref _credits);
                for (int i = 0; i < needed; i++)
                {
                    if (!_running) break;
                    Interlocked.Increment(ref _credits);
                    SendOnePublishAsync().Forget(_logger ?? NullLogger.Instance, "SendOnePublishAsync(credit fill)");
                }
            }
        }

        private void ProcessOwnPublishResponse(PublishResponse response)
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

        internal void OnPublishResponseForwarded(byte[] body)
        {
            try
            {
                var decoder = new BinaryDecoder(body);
                var response = PublishResponse.Decode(decoder);

                if (response.Parameters.SubscriptionId == this.SubscriptionId)
                {
                    ProcessOwnPublishResponse(response);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: error processing forwarded PublishResponse");
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

            lock (_lock)
            {
                if (!MonitoredItems.TryGetValue(clientHandle, out item))
                    return;
                capturedValue = value?.Value?.Value;
                capturedStatus = value?.StatusCode ?? new StatusCode();
                item.LastValue = capturedValue;
                item.LastStatus = capturedStatus;
            }

            try { item.OnDataChange?.Invoke(item.NodeId, capturedValue, capturedStatus); }
            catch (Exception ex) { _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: OnDataChange handler threw"); }

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
                var handlesToRemove = MonitoredItems
                    .Where(kvp => monitoredItemIds.Contains(kvp.Value.MonitoredItemId))
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

            _cts.Dispose();
        }

        internal void StopPublishing()
        {
            lock (_lock)
            {
                _running = false;
                try { _cts.Cancel(); } catch { }
                _publishTask = null;
            }
        }

        /// <summary>
        /// Stops the publish loop and releases all resources held by this subscription.
        /// Safe to call multiple times; subsequent calls have no effect.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

            StopPublishing();

            _router?.Unregister(SubscriptionId);

            try { _cts.Dispose(); } catch { }
        }
    }

    internal static class SubscriptionExtensions
    {
        internal static Task<Subscription> CreateSubscriptionAsync(this SubscriptionRouter router, double publishingInterval = 1000.0, bool autoStart = true)
        {
            return SubscriptionManager.CreateSubscriptionAsync(router, publishingInterval, autoStart);
        }

        internal static Task<MonitoredItem> SubscribeAsync(this Subscription subscription, NodeId nodeId, DataChangeHandler? handler = null, uint queueSize = 0)
        {
            return subscription.AddMonitoredItemAsync(nodeId, handler, queueSize);
        }

        internal static Task SubscribeAsync(this Subscription subscription, NodeId[] nodeIds, DataChangeHandler? handler = null, uint queueSize = 0)
        {
            return subscription.AddMonitoredItemsAsync(nodeIds, handler, queueSize);
        }
    }
}
