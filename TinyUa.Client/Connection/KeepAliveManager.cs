using TinyUa.Core;
using System;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Client.Services;

namespace TinyUa.Client.Connection
{

    /// <summary>
    /// Keeps the connection's server-side state alive on two levels:
    /// (1) periodically renews the secure channel token before it expires, and
    /// (2) reads <c>Server.ServerStatus.State</c> when the session has been IDLE for the
    /// configured threshold, so the SESSION lifetime is refreshed even with no application
    /// traffic — OpenSecureChannel renewal alone does not count as session activity, while
    /// every ordinary request already does. The heartbeat is idle-gated: as long as reads/
    /// writes/publish requests are flowing, no keep-alive read is sent at all.
    /// </summary>
    internal class KeepAliveManager : IDisposable
    {
        // Scheduling slack: a timer tick landing marginally before the exact idle threshold
        // still counts as "idle reached" instead of re-arming for a few milliseconds.
        private const int IdleSlackMs = 50;

        private readonly UaConnection _client;
        private readonly ILogger _logger;
        private Timer? _channelRenewTimer;
        private Timer? _sessionKeepAliveTimer;
        private volatile bool _disposed;
        private readonly int _channelLifetimeMs;
        private readonly int _sessionIdleThresholdMs;
        private int _channelKeepAliveCount;
        private int _sessionKeepAliveCount;
        private int _sessionReadInFlight;
        private int _channelRenewInFlight;

        // Server_ServerStatus_State (i=2259): the cheapest standard node to poll for liveness —
        // a scalar Int32, mandated by the spec on every server.
        private static readonly NodeId SessionKeepAliveNode = new NodeId(2259u);

        internal event Action? ChannelRenewed;

        /// <summary>Raised after each successful session keep-alive read.</summary>
        internal event Action? SessionKeepAlive;

        internal int ChannelKeepAliveCount => _channelKeepAliveCount;
        internal int SessionKeepAliveCount => Volatile.Read(ref _sessionKeepAliveCount);

        internal KeepAliveManager(UaConnection client, int sessionTimeoutMs, int channelLifetimeMs,
            ILogger? logger = null, int sessionKeepAliveIntervalMs = 0)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _logger = logger ?? NullLogger.Instance;
            _channelLifetimeMs = channelLifetimeMs > 0 ? channelLifetimeMs : 3600000;
            _sessionIdleThresholdMs = ComputeSessionIdleThreshold(sessionTimeoutMs, sessionKeepAliveIntervalMs);
        }

        /// <summary>
        /// Resolves the effective session idle threshold (heartbeat fires only after this much
        /// idle time; under continuous idle it becomes the heartbeat interval):
        /// negative configured value disables the heartbeat (returns 0); a positive value is
        /// used as given (floored to 250 ms); 0 selects automatic — a quarter of the session
        /// timeout, clamped to [1000, 60000] ms (60 s when the timeout is unknown).
        /// </summary>
        internal static int ComputeSessionIdleThreshold(int sessionTimeoutMs, int configuredMs)
        {
            if (configuredMs < 0) return 0;
            if (configuredMs > 0) return Math.Max(250, configuredMs);
            if (sessionTimeoutMs <= 0) return 60000;
            return Math.Clamp(sessionTimeoutMs / 4, 1000, 60000);
        }

        internal void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(KeepAliveManager));

            var interval = ComputeChannelRenewInterval(_channelLifetimeMs);
            _channelRenewTimer = new Timer(OnChannelRenew, null, interval, interval);

            // One-shot timer, re-armed after every tick: either to the moment the idle threshold
            // will next be reached (when traffic flowed in between) or by a full threshold after
            // a heartbeat. This way the heartbeat never fires while ordinary requests are flowing.
            if (_sessionIdleThresholdMs > 0)
                _sessionKeepAliveTimer = new Timer(OnSessionKeepAlive, null,
                    _sessionIdleThresholdMs, Timeout.Infinite);
        }

        internal static int ComputeChannelRenewInterval(int channelLifetimeMs)
        {
            var lifetime = channelLifetimeMs > 0 ? channelLifetimeMs : 3600000;
            return Math.Max(1000, Math.Min((int)(lifetime * 0.75), 3600000));
        }

        private void OnChannelRenew(object? state)
        {
            if (_disposed) return;
            if (Interlocked.CompareExchange(ref _channelRenewInFlight, 1, 0) != 0)
                return;

            Task.Run(async () =>
            {
                try
                {
                    if (_disposed) return;
                    await _client.RenewSecureChannelAsync((uint)_channelLifetimeMs).ConfigureAwait(false);
                    Interlocked.Increment(ref _channelKeepAliveCount);
                    ChannelRenewed?.Invoke();
                }
                catch (Exception ex)
                {

                    _logger.LogWarning(ex, "Channel Renew FAILED — connection may be dead");
                }
                finally
                {
                    Interlocked.Exchange(ref _channelRenewInFlight, 0);
                }
            }).Forget(_logger, nameof(OnChannelRenew));
        }

        private void OnSessionKeepAlive(object? state)
        {
            if (_disposed) return;

            // Idle gate: any request sent since the last check already refreshed the session
            // lifetime on the server, so no heartbeat is needed — just re-arm the timer for the
            // moment the idle threshold would next be reached.
            var idle = _client.IdleMilliseconds;
            if (idle < _sessionIdleThresholdMs - IdleSlackMs)
            {
                RearmSessionTimer(_sessionIdleThresholdMs - idle);
                return;
            }

            // Skip this tick if the previous read is still in flight (slow or hung server), so
            // keep-alive reads never pile up.
            if (Interlocked.CompareExchange(ref _sessionReadInFlight, 1, 0) != 0)
            {
                RearmSessionTimer(_sessionIdleThresholdMs);
                return;
            }

            Task.Run(async () =>
            {
                try
                {
                    if (_disposed) return;
                    var results = await _client.ReadAsync(SessionKeepAliveNode, AttributeId.Value).ConfigureAwait(false);
                    // An absent StatusCode field means Good per the OPC UA DataValue encoding.
                    if (results is { Length: > 0 } && results[0] is { } dv && (dv.StatusCode?.IsGood ?? true))
                    {
                        var count = Interlocked.Increment(ref _sessionKeepAliveCount);
                        _logger.LogDebug($"Session keep-alive read OK (count={count})");
                        SessionKeepAlive?.Invoke();
                    }
                    else
                    {
                        _logger.LogWarning("Session keep-alive read returned a bad or empty result");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Session keep-alive read FAILED — connection may be dead");
                }
                finally
                {
                    Interlocked.Exchange(ref _sessionReadInFlight, 0);
                    RearmSessionTimer(_sessionIdleThresholdMs);
                }
            }).Forget(_logger, nameof(OnSessionKeepAlive));
        }

        private void RearmSessionTimer(long dueMs)
        {
            if (_disposed) return;
            var due = (int)Math.Clamp(dueMs, 250, int.MaxValue);
            try { _sessionKeepAliveTimer?.Change(due, Timeout.Infinite); }
            catch (ObjectDisposedException) { }
        }

        internal void Stop()
        {
            _channelRenewTimer?.Dispose();
            _channelRenewTimer = null;
            _sessionKeepAliveTimer?.Dispose();
            _sessionKeepAliveTimer = null;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }
    }
}
