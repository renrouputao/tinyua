using TinyUa.Core;
using TinyUa.Core.Types;
using TinyUa.Client.Services;

namespace TinyUa.Client.Subscriptions;

public partial class Subscription
{
    internal void ReleaseAcknowledgements()
    {
        lock (_lock) _acknowledgementsInFlight.Clear();
    }

    internal uint[] TakeAcknowledgements()
    {
        lock (_lock)
        {
            var result = _acknowledgements.Where(x => !_acknowledgementsInFlight.Contains(x)).ToArray();
            foreach (var seq in result) _acknowledgementsInFlight.Add(seq);
            return result;
        }
    }

    internal void CompleteAcknowledgement(uint sequence, bool accepted)
    {
        lock (_lock)
        {
            _acknowledgementsInFlight.Remove(sequence);
            if (accepted) _acknowledgements.Remove(sequence);
        }
    }

    internal async Task<MonitoredItem[]> AddBatchAsync(NodeId[] nodes, double interval,
        DataChangeHandler? handler, uint queueSize, DataChangeHandlerEx? handlerEx, CancellationToken ct)
    {
        await _mutationLock.WaitAsync(ct).ConfigureAwait(false);
        var added = new List<MonitoredItem>();
        try
        {
            ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
            // Conservative batches; a server may additionally lower its operation limit.
            int batchSize = 100;
            for (int offset = 0; offset < nodes.Length;)
            {
                ct.ThrowIfCancellationRequested();
                var batch = nodes.Skip(offset).Take(batchSize).Select(node => new MonitoredItem
                {
                    NodeId = node ?? throw new ArgumentException("Null monitored node."),
                    ClientHandle = (uint)Interlocked.Increment(ref _nextClientHandle),
                    SamplingInterval = interval,
                    QueueSize = queueSize,
                    OnDataChange = handler,
                    OnDataChangeEx = handlerEx
                }).ToArray();
                lock (_lock)
                    foreach (var item in batch)
                    {
                        // This ID is a stable client handle, independent of server session IDs.
                        item.MonitoredItemId = item.ClientHandle;
                        MonitoredItems[item.ClientHandle] = item;
                    }
                MonitoredItemCreateResult[]? results;
                try
                {
                    results = await _router.CreateMonitoredItemsAsync(SubscriptionId, batch.Select(i => i.NodeId).ToArray(),
                        AttributeId.Value, interval, batch.Select(i => i.ClientHandle).ToArray(), queueSize, ct).ConfigureAwait(false);
                }
                catch (UaException ex) when (ex.StatusCode == 0x80100000 && batchSize > 1)
                {
                    lock (_lock) foreach (var item in batch) MonitoredItems.Remove(item.ClientHandle);
                    batchSize = Math.Max(1, batchSize / 2);
                    continue;
                }
                catch
                {
                    lock (_lock) foreach (var item in batch) MonitoredItems.Remove(item.ClientHandle);
                    throw;
                }
                if (results?.Length != batch.Length)
                {
                    lock (_lock) foreach (var item in batch) MonitoredItems.Remove(item.ClientHandle);
                    throw new UaException(0x80070000, "Monitored item result count mismatch.");
                }
                StatusCode? failure = null;
                lock (_lock)
                {
                    for (int i = 0; i < batch.Length; i++)
                    {
                        if (results[i].StatusCode.IsGood)
                        {
                            batch[i].ServerMonitoredItemId = results[i].MonitoredItemId;
                            added.Add(batch[i]);
                        }
                        else
                        {
                            MonitoredItems.Remove(batch[i].ClientHandle);
                            failure ??= results[i].StatusCode;
                        }
                    }
                }
                ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
                failure?.Check();
                offset += batch.Length;
            }
            return added.ToArray();
        }
        finally { _mutationLock.Release(); }
    }

    internal async Task<StatusCode[]> DeleteMonitoredItemsAsync(uint[] monitoredItemIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(monitoredItemIds);
        await _mutationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
            MonitoredItem?[] items;
            lock (_lock) items = monitoredItemIds.Select(id => MonitoredItems.Values.FirstOrDefault(i => i.MonitoredItemId == id)).ToArray();
            var results = new StatusCode[items.Length];
            var known = items.Select((item, index) => (item, index)).Where(x => x.item != null).ToArray();
            for (int i = 0; i < items.Length; i++) results[i] = new StatusCode(0x80420000);
            if (known.Length == 0) return results;
            var deleted = await _router.DeleteMonitoredItemsAsync(SubscriptionId,
                known.Select(x => x.item!.ServerMonitoredItemId).ToArray(), cancellationToken).ConfigureAwait(false);
            if (deleted.Length != known.Length) throw new UaException(0x80070000, "Delete result count mismatch.");
            lock (_lock)
                for (int i = 0; i < known.Length; i++)
                {
                    results[known[i].index] = deleted[i];
                    if (deleted[i].IsGood || deleted[i].Value == 0x80420000)
                        MonitoredItems.Remove(known[i].item!.ClientHandle);
                }
            return results;
        }
        finally { _mutationLock.Release(); }
    }

    internal async Task RebuildAsync(CancellationToken ct)
    {
        await _mutationLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
            StopPublishing();
            var response = await _router.CreateSubscriptionAsync(PublishingInterval, LifetimeCount, MaxKeepAliveCount, ct).ConfigureAwait(false);
            if (IsSubscriptionDisposed)
            {
                await _router.DeleteSubscriptionsAsync(new[] { response.SubscriptionId }, ct).ConfigureAwait(false);
                throw new ObjectDisposedException(nameof(Subscription));
            }
            MonitoredItem[] items;
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
                _router.Unregister(SubscriptionId, this);
                SubscriptionId = response.SubscriptionId;
                PublishingInterval = response.RevisedPublishingInterval;
                LifetimeCount = response.RevisedLifetimeCount;
                MaxKeepAliveCount = response.RevisedMaxKeepAliveCount;
                _router.Register(SubscriptionId, this);
                _generation++;
                _lastSequenceNumber = 0;
                _acknowledgements.Clear();
                _acknowledgementsInFlight.Clear();
                items = MonitoredItems.Values.ToArray();
            }
            foreach (var group in items.GroupBy(item => (item.SamplingInterval, item.QueueSize)))
            {
                var pending = group.ToArray();
                var batchSize = 100;
                for (var offset = 0; offset < pending.Length;)
                {
                    ObjectDisposedException.ThrowIf(IsSubscriptionDisposed, this);
                    var batch = pending.Skip(offset).Take(batchSize).ToArray();
                    MonitoredItemCreateResult[]? results;
                    try
                    {
                        results = await _router.CreateMonitoredItemsAsync(SubscriptionId, batch.Select(i => i.NodeId).ToArray(),
                            AttributeId.Value, group.Key.SamplingInterval, batch.Select(i => i.ClientHandle).ToArray(), group.Key.QueueSize, ct).ConfigureAwait(false);
                    }
                    catch (UaException ex) when (ex.StatusCode == 0x80100000 && batchSize > 1)
                    { batchSize = Math.Max(1, batchSize / 2); continue; }
                    if (results?.Length != batch.Length) throw new UaException(0x80070000, "Rebuild result count mismatch.");
                    for (int i = 0; i < batch.Length; i++)
                    {
                        results[i].StatusCode.Check();
                        batch[i].ServerMonitoredItemId = results[i].MonitoredItemId;
                    }
                    offset += batch.Length;
                }
            }
        }
        catch
        {
            // Do not retain a half-built subscription as if recovery had succeeded.
            try
            {
                if (!ct.IsCancellationRequested)
                    await _router.DeleteSubscriptionsAsync(new[] { SubscriptionId }, ct).ConfigureAwait(false);
            }
            catch { }
            throw;
        }
        finally { _mutationLock.Release(); }
    }
}
