using TinyUa.Core;
using System;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;

namespace TinyUa.Client.Connection
{

    internal class KeepAliveManager : IDisposable
    {
        private readonly UaConnection _client;
        private readonly ILogger _logger;
        private Timer? _channelRenewTimer;
        private bool _disposed;
        private readonly int _channelLifetimeMs;
        private int _channelKeepAliveCount;

        internal event Action? ChannelRenewed;

        internal int ChannelKeepAliveCount => _channelKeepAliveCount;

        internal KeepAliveManager(UaConnection client, int sessionTimeoutMs, int channelLifetimeMs, ILogger? logger = null)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _logger = logger ?? NullLogger.Instance;
            _channelLifetimeMs = channelLifetimeMs > 0 ? channelLifetimeMs : 3600000;
        }

        internal void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(KeepAliveManager));

            var interval = Math.Max(1000, Math.Min((int)(_channelLifetimeMs * 0.75), 3600000));
            _channelRenewTimer = new Timer(OnChannelRenew, null, interval, interval);
        }

        private void OnChannelRenew(object? state)
        {
            if (_disposed) return;

            Task.Run(async () =>
            {
                if (_disposed) return;
                try
                {
                    await _client.RenewSecureChannelAsync((uint)_channelLifetimeMs).ConfigureAwait(false);
                    Interlocked.Increment(ref _channelKeepAliveCount);
                    ChannelRenewed?.Invoke();
                }
                catch (Exception ex)
                {

                    _logger.LogWarning(ex, "Channel Renew FAILED — connection may be dead");
                }
            }).Forget(_logger, nameof(OnChannelRenew));
        }

        internal void Stop()
        {
            _channelRenewTimer?.Dispose();
            _channelRenewTimer = null;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }
    }
}
