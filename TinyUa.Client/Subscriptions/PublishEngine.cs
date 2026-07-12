using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Client.Services;

namespace TinyUa.Client.Subscriptions
{
    /// <summary>
    /// Session-level publish pump. OPC UA Publish requests are not tied to a particular
    /// subscription — any response may carry data for any subscription — so a single engine
    /// keeps N requests in flight for the whole session, decodes each response once, dispatches
    /// it to the owning subscription via the router registry, and tops the pool back up.
    /// Subscriptions attach on StartPublishing and detach on StopPublishing/Dispose; the pump
    /// runs while at least one subscription is attached.
    /// </summary>
    internal sealed class PublishEngine
    {
        private readonly SubscriptionRouter _router;
        private readonly ILogger _logger;
        private readonly object _lock = new();
        private readonly HashSet<Subscription> _attached = new();
        private int _inFlight;
        private int _maxInFlight = 2;
        private volatile bool _running;
        private Timer? _fallbackTimer;

        internal PublishEngine(SubscriptionRouter router, ILogger logger)
        {
            _router = router;
            _logger = logger;
        }

        internal int InFlight => Volatile.Read(ref _inFlight);
        internal bool IsRunning => _running;

        internal void Attach(Subscription subscription, int maxPublishRequests)
        {
            lock (_lock)
            {
                _attached.Add(subscription);
                if (maxPublishRequests > 0)
                    _maxInFlight = Math.Max(_maxInFlight, maxPublishRequests);
                if (!_running)
                {
                    _running = true;
                    // Safety net: if a response is lost without either completion callback firing
                    // (which the callback contract should prevent), the periodic top-up restores
                    // the in-flight pool instead of letting publishing silently stall.
                    _fallbackTimer = new Timer(_ => TopUp(), null, 30000, 30000);
                    _logger.LogDebug("PublishEngine: started");
                }
            }
            TopUp();
        }

        internal void Detach(Subscription subscription)
        {
            lock (_lock)
            {
                _attached.Remove(subscription);
                if (_attached.Count == 0 && _running)
                {
                    _running = false;
                    _fallbackTimer?.Dispose();
                    _fallbackTimer = null;
                    // In-flight requests drain via their callbacks (which no-op once stopped);
                    // resetting here lets a fresh attach start with a clean pool.
                    Volatile.Write(ref _inFlight, 0);
                    _logger.LogDebug("PublishEngine: stopped (no attached subscriptions)");
                }
            }
        }

        private void TopUp()
        {
            // Cap the sends triggered by one TopUp call: a synchronously failing send (e.g. dead
            // or not-yet-connected transport) releases its in-flight slot immediately, so an
            // unbounded refill loop would spin hot forever. Any shortfall is recovered by the
            // response callbacks and the fallback timer.
            for (int fired = 0; _running && fired < _maxInFlight;)
            {
                int current = Volatile.Read(ref _inFlight);
                if (current >= _maxInFlight) return;
                if (Interlocked.CompareExchange(ref _inFlight, current + 1, current) != current) continue;
                fired++;
                SendOnePublishAsync().Forget(_logger, "PublishEngine.SendOnePublish");
            }
        }

        /// <summary>
        /// Acknowledges the latest sequence number of every attached subscription, mirroring the
        /// per-subscription ack behavior of the previous per-subscription pumps.
        /// </summary>
        private SubscriptionAcknowledgement[] BuildAcknowledgements()
        {
            lock (_lock)
            {
                List<SubscriptionAcknowledgement>? acks = null;
                foreach (var sub in _attached)
                {
                    var seq = sub.LastSequenceNumber;
                    if (seq == 0) continue;
                    (acks ??= new List<SubscriptionAcknowledgement>()).Add(new SubscriptionAcknowledgement
                    {
                        SubscriptionId = sub.SubscriptionId,
                        SequenceNumber = seq
                    });
                }
                return acks?.ToArray() ?? Array.Empty<SubscriptionAcknowledgement>();
            }
        }

        private async Task SendOnePublishAsync()
        {
            if (!_running)
            {
                Interlocked.Decrement(ref _inFlight);
                return;
            }

            try
            {
                await _router.SendPublishAsync(BuildAcknowledgements(), OnPublishResponse, OnPublishFaulted)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Synchronous send failure: per the SendRequestNoWait contract no callback will
                // fire, so the in-flight slot is released here (and only here).
                Interlocked.Decrement(ref _inFlight);
                _logger.LogDebug(ex, "PublishEngine: publish send failed");
            }
        }

        private void OnPublishFaulted(Exception ex)
        {
            Interlocked.Decrement(ref _inFlight);
            _logger.LogDebug(ex, "PublishEngine: publish request faulted");
        }

        private void OnPublishResponse(byte[] body)
        {
            Interlocked.Decrement(ref _inFlight);
            try
            {
                var decoder = new BinaryDecoder(body);
                var response = PublishResponse.Decode(decoder);

                var subscriptionId = response.Parameters.SubscriptionId;
                if (_router.TryGet(subscriptionId, out var target) && target != null && !target.IsSubscriptionDisposed)
                {
                    target.HandlePublishResponse(response);
                }
                else
                {
                    _logger.LogDebug($"PublishEngine: PublishResponse for unknown/disposed sub {subscriptionId}");
                }
            }
            catch (Exception ex)
            {
                // After Detach, in-flight publishes commonly complete with BadNoSubscription /
                // BadSessionClosed service faults — expected teardown noise, not a warning.
                if (!_running)
                    _logger.LogDebug(ex, "PublishEngine: PublishResponse fault after stop (expected during teardown)");
                else
                    _logger.LogWarning(ex, "PublishEngine: error processing PublishResponse");
            }
            finally
            {
                if (_running)
                    TopUp();
            }
        }
    }
}
