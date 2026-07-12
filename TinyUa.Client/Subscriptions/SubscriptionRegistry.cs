using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace TinyUa.Client.Subscriptions
{
    /// <summary>
    /// Tracks the client's active subscriptions and deduplicates concurrent subscription creation
    /// at the same publishing interval, so callers asking for an equal interval share one server
    /// subscription instead of racing to create duplicates.
    /// </summary>
    internal sealed class SubscriptionRegistry
    {
        private readonly List<Subscription> _active = new();
        private readonly Dictionary<double, TaskCompletionSource<Subscription>> _pendingCreates = new();
        private readonly object _lock = new();

        internal void Add(Subscription subscription)
        {
            lock (_lock)
                _active.Add(subscription);
        }

        internal void Remove(Subscription subscription)
        {
            lock (_lock)
                _active.Remove(subscription);
        }

        internal Subscription[] Snapshot()
        {
            lock (_lock)
                return _active.ToArray();
        }

        /// <summary>
        /// Removes and returns all active subscriptions and faults every pending create with
        /// <paramref name="pendingException"/>. Used on shutdown.
        /// </summary>
        internal Subscription[] DrainForShutdown(Exception pendingException)
        {
            lock (_lock)
            {
                var subs = _active.ToArray();
                _active.Clear();

                foreach (var kvp in _pendingCreates)
                    kvp.Value.TrySetException(pendingException);
                _pendingCreates.Clear();

                return subs;
            }
        }

        /// <summary>
        /// Returns an existing subscription whose publishing interval matches within 0.001 ms, or
        /// creates one via <paramref name="factory"/>. Concurrent calls for the same interval
        /// share a single in-flight creation.
        /// </summary>
        internal async Task<Subscription> GetOrCreateAsync(double interval, Func<Task<Subscription>> factory)
        {
            TaskCompletionSource<Subscription>? pending;
            bool iAmCreator;

            // Dedup and pending-create tracking must use the same resolution, otherwise two
            // near-equal intervals (e.g. 500.0 vs 500.0004) pass the reuse scan yet get distinct
            // raw-double dictionary keys and create duplicate subscriptions. Quantize the key to
            // the same 0.001 ms granularity used by the reuse comparison below.
            double intervalKey = Math.Round(interval, 3);

            lock (_lock)
            {
                foreach (var sub in _active)
                {
                    if (Math.Abs(sub.PublishingInterval - interval) < 0.001)
                        return sub;
                }

                if (_pendingCreates.TryGetValue(intervalKey, out pending))
                {
                    iAmCreator = false;
                }
                else
                {
                    iAmCreator = true;
                    pending = new TaskCompletionSource<Subscription>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingCreates[intervalKey] = pending;
                }
            }

            if (!iAmCreator)
                return await pending!.Task.ConfigureAwait(false);

            try
            {
                var sub = await factory().ConfigureAwait(false);
                pending!.SetResult(sub);
                return sub;
            }
            catch (Exception ex)
            {
                pending!.SetException(ex);
                throw;
            }
            finally
            {
                lock (_lock)
                    _pendingCreates.Remove(intervalKey);
            }
        }
    }
}
