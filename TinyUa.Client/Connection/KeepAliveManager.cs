using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Client.Services;

namespace TinyUa.Client.Connection;

/// <summary>One cancellable scheduler owns channel renewal and idle session heartbeats.</summary>
internal sealed class KeepAliveManager : IDisposable
{
    private readonly UaConnection _client;
    private readonly ILogger _logger;
    private readonly int _channelLifetimeMs;
    private readonly int _sessionIdleThresholdMs;
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private int _disposed;
    private int _channelKeepAliveCount;
    private int _sessionKeepAliveCount;
    private static readonly NodeId SessionKeepAliveNode = new(2259u);

    internal event Action? ChannelRenewed;
    internal event Action? SessionKeepAlive;
    internal int ChannelKeepAliveCount => Volatile.Read(ref _channelKeepAliveCount);
    internal int SessionKeepAliveCount => Volatile.Read(ref _sessionKeepAliveCount);

    internal KeepAliveManager(UaConnection client, int sessionTimeoutMs, int channelLifetimeMs,
        ILogger? logger = null, int sessionKeepAliveIntervalMs = 0)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? NullLogger.Instance;
        _channelLifetimeMs = channelLifetimeMs > 0 ? channelLifetimeMs : 3600000;
        _sessionIdleThresholdMs = ComputeSessionIdleThreshold(sessionTimeoutMs, sessionKeepAliveIntervalMs);
    }

    internal static int ComputeSessionIdleThreshold(int sessionTimeoutMs, int configuredMs)
    {
        if (configuredMs < 0) return 0;
        if (configuredMs > 0) return sessionTimeoutMs > 0
            ? Math.Max(1, Math.Min(Math.Max(250, configuredMs), sessionTimeoutMs / 4)) : Math.Max(250, configuredMs);
        if (sessionTimeoutMs <= 0) return 60000;
        return Math.Clamp(sessionTimeoutMs / 4, 1, 60000);
    }

    internal static int ComputeChannelRenewInterval(int channelLifetimeMs)
        => (int)Math.Clamp((channelLifetimeMs > 0 ? channelLifetimeMs : 3600000) * 0.75, 1, 3600000);

    internal void Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _loop ??= RunAsync(_stop.Token);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var renewInterval = ComputeChannelRenewInterval(_channelLifetimeMs);
        var nextRenew = Environment.TickCount64 + renewInterval;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var delay = nextRenew - Environment.TickCount64;
                if (_sessionIdleThresholdMs > 0)
                    delay = Math.Min(delay, _sessionIdleThresholdMs - _client.IdleMilliseconds);
                await Task.Delay((int)Math.Clamp(delay, 1, int.MaxValue), ct).ConfigureAwait(false);
                if (Environment.TickCount64 >= nextRenew)
                {
                    await _client.RenewSecureChannelAsync((uint)_channelLifetimeMs, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    Interlocked.Increment(ref _channelKeepAliveCount);
                    ChannelRenewed?.Invoke();
                    nextRenew = Environment.TickCount64 + renewInterval;
                }
                if (_sessionIdleThresholdMs > 0 && _client.IdleMilliseconds >= _sessionIdleThresholdMs)
                {
                    var results = await _client.ReadAsync(SessionKeepAliveNode, AttributeId.Value, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (results is { Length: > 0 } && (results[0].StatusCode?.IsGood ?? true))
                    {
                        Interlocked.Increment(ref _sessionKeepAliveCount);
                        SessionKeepAlive?.Invoke();
                    }
                    else _logger.LogWarning("Session heartbeat returned a bad or empty result.");
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Keep-alive failed; scheduling connection recovery.");
            if (!ct.IsCancellationRequested) _client.ReportConnectionFailure(ex);
        }
    }

    internal void Stop()
    {
        try { _stop.Cancel(); } catch (ObjectDisposedException) { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Stop();
        CleanupAsync().Forget(_logger, nameof(KeepAliveManager));
    }

    private async Task CleanupAsync()
    {
        if (_loop != null) await _loop.ConfigureAwait(false);
        _stop.Dispose();
    }
}
