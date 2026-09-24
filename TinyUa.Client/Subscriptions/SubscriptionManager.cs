using TinyUa.Core;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Channels;
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
        internal static async Task<Subscription> CreateSubscriptionAsync(SubscriptionRouter router, double publishingInterval = 1000.0, bool autoStart = true, int maxPublishRequests = 2, ILogger? logger = null, SubscriptionDispatchOptions? dispatchOptions = null, CancellationToken cancellationToken = default)
        {
            var result = await router.CreateSubscriptionAsync(publishingInterval, cancellationToken: cancellationToken).ConfigureAwait(false);
            var subscription = new Subscription(
                router,
                result.SubscriptionId,
                result.RevisedPublishingInterval,
                result.RevisedLifetimeCount,
                result.RevisedMaxKeepAliveCount,
                maxPublishRequests,
                logger,
                dispatchOptions);

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
        internal uint ServerMonitoredItemId { get; set; }
        internal uint QueueSize { get; set; }
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
    public partial class Subscription : IDisposable
    {
        private readonly SubscriptionRouter _router = null!;
        private readonly ILogger _logger;
        private readonly object _lock = new();
        private readonly int _maxPublishRequests;
        private readonly SubscriptionDispatchOptions _dispatchOptions;
        private readonly Channel<DispatchItem> _dispatchQueue;
        private readonly CancellationTokenSource _dispatchCancellation = new();
        private readonly SemaphoreSlim _enqueueLock = new(1, 1);
        private readonly Task _dispatchWorker;
        private int _isDisposed;
        private int _dispatchStopped;
        private int _generation;
        private int _deleteSent;
        internal volatile bool _running;
        internal event Action<Subscription>? Disposed;
        private readonly SemaphoreSlim _mutationLock = new(1, 1);
        private readonly HashSet<uint> _acknowledgements = new();
        private readonly HashSet<uint> _acknowledgementsInFlight = new();
        private volatile uint _lastSequenceNumber;
        private int _publishCount;
        private int _notificationCount;
        private int _pendingNotificationMessages;
        private long _droppedNotificationMessages;

        internal uint SubscriptionId { get; private set; }
        internal double PublishingInterval { get; private set; }
        internal uint LifetimeCount { get; private set; }
        internal uint MaxKeepAliveCount { get; private set; }
        internal Dictionary<uint, MonitoredItem> MonitoredItems { get; } = new();
        private int _nextClientHandle = 0;

        internal event Action<NodeId, object?, StatusCode>? OnDataChange;

        internal event Action? OnKeepAlive;

        internal event Action<Exception>? OnPublishError;

        internal int PublishCount => _publishCount;
        internal int NotificationCount => _notificationCount;
        internal uint LastSequenceNumber => _lastSequenceNumber;

        /// <summary>Number of Publish responses currently queued for callback dispatch.</summary>
        public int PendingNotificationMessages => Math.Max(0, Volatile.Read(ref _pendingNotificationMessages));

        /// <summary>Number of Publish responses intentionally dropped by the configured overflow policy.</summary>
        public long DroppedNotificationMessages => Interlocked.Read(ref _droppedNotificationMessages);

        internal bool IsPublishing => _running;
        internal bool IsSubscriptionDisposed => Volatile.Read(ref _isDisposed) != 0;

        internal Subscription(SubscriptionRouter router, uint subscriptionId,
            double publishingInterval, uint lifetimeCount, uint maxKeepAliveCount,
            int maxPublishRequests = 2, ILogger? logger = null, SubscriptionDispatchOptions? dispatchOptions = null)
        {
            _router = router;
            _logger = logger ?? NullLogger.Instance;
            SubscriptionId = subscriptionId;
            PublishingInterval = publishingInterval;
            LifetimeCount = lifetimeCount;
            MaxKeepAliveCount = maxKeepAliveCount;
            _maxPublishRequests = Math.Max(1, maxPublishRequests);
            _dispatchOptions = (dispatchOptions ?? new SubscriptionDispatchOptions()).Clone();
            var capacity = Math.Max(1, _dispatchOptions.QueueCapacity);
            _dispatchQueue = Channel.CreateBounded<DispatchItem>(new BoundedChannelOptions(capacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false
            });
            _dispatchWorker = ProcessPublishResponsesAsync();
            _running = false;
            _lastSequenceNumber = 0;

            _router?.Register(subscriptionId, this);
        }

        /// <summary>
        /// Queues a decoded Publish response for this subscription's single callback worker.
        /// The enqueue lock preserves the router's response order when several Publish requests
        /// complete concurrently. With <see cref="NotificationOverflowPolicy.Wait"/>, this method
        /// waits for capacity; the Publish engine awaits it before replenishing its finite window.
        /// </summary>
        internal async Task EnqueuePublishResponseAsync(PublishResponse response)
        {
            await EnqueueDispatchAsync(new DispatchItem(response) { Generation = Volatile.Read(ref _generation) }).ConfigureAwait(false);
        }

        /// <summary>
        /// Routes a Republish result through the normal serial dispatch worker and completes only
        /// after its sequence number and callback processing have finished. Reconnect therefore
        /// keeps the same acknowledgement and backpressure semantics as live publishing.
        /// </summary>
        internal async Task EnqueueRepublishAsync(NotificationMessage message, CancellationToken cancellationToken = default)
        {
            var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            await EnqueueDispatchAsync(new DispatchItem(message, completion) { Generation = Volatile.Read(ref _generation) }, cancellationToken).ConfigureAwait(false);
            try
            {
                await completion.Task.WaitAsync(_dispatchCancellation.Token).WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_dispatchCancellation.IsCancellationRequested)
            {
            }
        }

        private async Task EnqueueDispatchAsync(DispatchItem item, CancellationToken cancellationToken = default)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(_dispatchCancellation.Token, cancellationToken);
            if (IsSubscriptionDisposed || Volatile.Read(ref _dispatchStopped) != 0)
            {
                item.Cancel();
                return;
            }

            try
            {
                await _enqueueLock.WaitAsync(linked.Token).ConfigureAwait(false);
                try
                {
                    if (IsSubscriptionDisposed || Volatile.Read(ref _dispatchStopped) != 0)
                    {
                        item.Cancel();
                        return;
                    }

                    if (_dispatchQueue.Writer.TryWrite(item))
                    {
                        Interlocked.Increment(ref _pendingNotificationMessages);
                        return;
                    }

                    switch (_dispatchOptions.OverflowPolicy)
                    {
                        case NotificationOverflowPolicy.Wait:
                            await _dispatchQueue.Writer.WriteAsync(item, linked.Token).ConfigureAwait(false);
                            Interlocked.Increment(ref _pendingNotificationMessages);
                            return;

                        case NotificationOverflowPolicy.DropOldest:
                            if (_dispatchQueue.Reader.TryRead(out var dropped))
                            {
                                Interlocked.Decrement(ref _pendingNotificationMessages);
                                RecordDroppedItem(dropped);
                            }
                            if (_dispatchQueue.Writer.TryWrite(item))
                            {
                                Interlocked.Increment(ref _pendingNotificationMessages);
                                return;
                            }
                            RecordDroppedItem(item);
                            return;

                        case NotificationOverflowPolicy.DropNewest:
                            RecordDroppedItem(item);
                            return;

                        default:
                            throw new InvalidOperationException($"Unknown notification overflow policy: {_dispatchOptions.OverflowPolicy}");
                    }
                }
                finally
                {
                    _enqueueLock.Release();
                }
            }
            catch (OperationCanceledException) when (_dispatchCancellation.IsCancellationRequested)
            {
                item.Cancel();
            }
            catch (ChannelClosedException) when (Volatile.Read(ref _dispatchStopped) != 0)
            {
                item.Cancel();
            }
        }

        private async Task ProcessPublishResponsesAsync()
        {
            try
            {
                await foreach (var item in _dispatchQueue.Reader.ReadAllAsync(_dispatchCancellation.Token).ConfigureAwait(false))
                {
                    Interlocked.Decrement(ref _pendingNotificationMessages);
                    try
                    {
                        if (!IsSubscriptionDisposed && item.Generation == Volatile.Read(ref _generation))
                        {
                            if (item.PublishResponse != null)
                                HandlePublishResponse(item.PublishResponse, item.Generation);
                            else if (item.RepublishedMessage != null)
                                HandleRepublishedNotification(item.RepublishedMessage, item.Generation);
                        }
                    }
                    finally
                    {
                        item.Complete();
                    }
                }
            }
            catch (OperationCanceledException) when (_dispatchCancellation.IsCancellationRequested)
            {
            }
            finally
            {
                while (_dispatchQueue.Reader.TryRead(out var item))
                    item.Cancel();
            }
        }

        private void RecordDroppedItem(DispatchItem item)
        {
            Interlocked.Increment(ref _droppedNotificationMessages);
            if (item.HasNotifications) AdvanceLastSequenceNumber(item.SequenceNumber, item.Generation);
            _logger?.LogWarning($"Subscription {SubscriptionId}: notification dispatch queue is full; dropped PublishResponse seq={_lastSequenceNumber} ({_dispatchOptions.OverflowPolicy})");
            item.Cancel();
        }

        private void AdvanceLastSequenceNumber(uint sequenceNumber, int? generation = null)
        {
            lock (_lock)
            {
                if (generation.HasValue && generation.Value != _generation) return;
                if (sequenceNumber == 0) return;
                _acknowledgements.Add(sequenceNumber);
                var current = _lastSequenceNumber;
                // OPC UA sequence numbers are unsigned and may wrap. A delta below half the
                // uint range is newer; this also prevents an older queued response from moving
                // the acknowledgement backwards after a newer response was dropped.
                if (current == 0 || unchecked(sequenceNumber - current) < 0x80000000u)
                    _lastSequenceNumber = sequenceNumber;
            }
        }

        private void StopDispatching()
        {
            if (Interlocked.Exchange(ref _dispatchStopped, 1) != 0)
                return;

            _dispatchQueue.Writer.TryComplete();
            _dispatchCancellation.Cancel();
        }

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, DataChangeHandler? handler = null,
            uint queueSize = 0, CancellationToken cancellationToken = default)
            => await AddMonitoredItemAsync(nodeId, PublishingInterval, handler, queueSize, null, cancellationToken).ConfigureAwait(false);

        internal async Task<MonitoredItem> AddMonitoredItemAsync(NodeId nodeId, double samplingInterval,
            DataChangeHandler? handler = null, uint queueSize = 0, DataChangeHandlerEx? handlerEx = null,
            CancellationToken cancellationToken = default)
            => (await AddBatchAsync(new[] { nodeId }, samplingInterval, handler, queueSize, handlerEx, cancellationToken).ConfigureAwait(false))[0];

        internal Task AddMonitoredItemsAsync(NodeId[] nodeIds, DataChangeHandler? handler = null, uint queueSize = 0,
            CancellationToken cancellationToken = default)
            => AddBatchAsync(nodeIds, PublishingInterval, handler, queueSize, null, cancellationToken);

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
        internal void HandlePublishResponse(PublishResponse response, int? generation = null)
        {
            Interlocked.Increment(ref _publishCount);
            try
            {
                response.ResponseHeader.ServiceResult.Check();

                var notificationMsg = response.Parameters.NotificationMessage;
                if (notificationMsg.NotificationData.Count > 0) AdvanceLastSequenceNumber(notificationMsg.SequenceNumber, generation);

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
                RaisePublishError(ex);
            }
        }

        private void HandleRepublishedNotification(NotificationMessage message, int? generation = null)
        {
            try
            {
                if (message.NotificationData.Count > 0) AdvanceLastSequenceNumber(message.SequenceNumber, generation);
                if (message.NotificationData.Count > 0)
                    ProcessNotification(message);
                else
                    OnKeepAlive?.Invoke();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, $"Subscription {SubscriptionId}: error processing republished notification");
                RaisePublishError(ex);
            }
        }

        internal void ProcessNotification(NotificationMessage message)
        {
            foreach (var data in message.NotificationData)
            {
                if (data.Body == null || data.Body.Length == 0) continue;

                if (data.TypeId == null || !data.TypeId.Equals(new NodeId(811u)))
                {
                    if (data.TypeId?.Equals(new NodeId(820u)) == true)
                        new StatusCode(new BinaryDecoder(data.Body).ReadUInt32()).Check();
                    continue;
                }

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

        internal async Task DeleteAsync(CancellationToken cancellationToken = default)
        {
            StopPublishing();

            _router?.Unregister(SubscriptionId, this);

            try
            {
                if (_router != null && Interlocked.Exchange(ref _deleteSent, 1) == 0)
                {
                    var results = await _router.DeleteSubscriptionsAsync(new[] { SubscriptionId }, cancellationToken).ConfigureAwait(false);
                    foreach (var status in results) status.Check();
                }
            }
            finally { Dispose(); }
        }

        /// <summary>
        /// Stops publishing and releases all resources held by this subscription.
        /// Safe to call multiple times; subsequent calls have no effect.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

            StopPublishing();

            StopDispatching();

            _router?.Unregister(SubscriptionId, this);
            Disposed?.Invoke(this);
            if (_router != null && Interlocked.Exchange(ref _deleteSent, 1) == 0)
                _router.DeleteSubscriptionsAsync(new[] { SubscriptionId }).Forget(_logger, "Dispose subscription on server");
        }

        private void RaisePublishError(Exception exception)
        {
            try { OnPublishError?.Invoke(exception); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Publish error handler threw"); }
        }

        private sealed class DispatchItem
        {
            internal int Generation { get; init; }
            internal PublishResponse? PublishResponse { get; }
            internal NotificationMessage? RepublishedMessage { get; }
            private readonly TaskCompletionSource<bool>? _completion;

            internal bool HasNotifications => (PublishResponse?.Parameters.NotificationMessage.NotificationData.Count
                ?? RepublishedMessage?.NotificationData.Count ?? 0) > 0;
            internal uint SequenceNumber => PublishResponse?.Parameters.NotificationMessage.SequenceNumber
                ?? RepublishedMessage?.SequenceNumber
                ?? 0;

            internal DispatchItem(PublishResponse response) => PublishResponse = response;

            internal DispatchItem(NotificationMessage message, TaskCompletionSource<bool> completion)
            {
                RepublishedMessage = message;
                _completion = completion;
            }

            internal void Complete() => _completion?.TrySetResult(true);

            internal void Cancel() => _completion?.TrySetCanceled();
        }
    }
}
