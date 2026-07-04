using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Core.Client.Services;
using TinyUa.Core.Client.Subscriptions;
using TinyUa.Core.Transport;
using TinyUa.Core.Security;

namespace TinyUa.Core.Client.Connection
{

    internal class ReconnectEngine : IDisposable
    {
        private readonly UaConnection _connection;
        private readonly UaClientOptions _options;
        private readonly ILogger _logger;
        private readonly List<SubscriptionTemplate> _subscriptionTemplates = new();
        private readonly object _lock = new();
        private volatile bool _reconnecting;
        private CancellationTokenSource? _reconnectCts;
        private TaskCompletionSource<bool>? _pendingReconnect;

        private NodeId? _lastSessionId;
        private NodeId? _lastAuthToken;

        internal bool IsReconnecting => _reconnecting;

        internal event Action? ReconnectStarted;
        internal event Action<int, int>? ReconnectBackoff;
        internal event Action<bool>? ReconnectCompleted;
        internal event Action? ReconnectFailed;

        internal ReconnectEngine(UaConnection connection, UaClientOptions options, ILogger? logger = null)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? NullLogger.Instance;
        }

        internal void OnSessionEstablished(NodeId sessionId, NodeId authToken)
        {
            _lastSessionId = sessionId;
            _lastAuthToken = authToken;
        }

        internal void RegisterSubscription(SubscriptionTemplate template, Subscription? activeSubscription = null)
        {
            template.ActiveSubscription = activeSubscription;
            lock (_lock)
            {
                var existing = _subscriptionTemplates.Find(t => t.SubscriptionId == template.SubscriptionId);
                if (existing != null)
                {
                    foreach (var item in template.Items)
                    {
                        if (!existing.Items.Any(i => i.NodeId == item.NodeId))
                            existing.Items.Add(item);
                    }
                }
                else
                {
                    _subscriptionTemplates.Add(template);
                }
            }
        }

        internal void UnregisterSubscription(uint subscriptionId)
        {
            lock (_lock)
                _subscriptionTemplates.RemoveAll(t => t.SubscriptionId == subscriptionId);
        }

        internal async Task<bool> ReconnectAsync(string endpointUrl, Func<SubscriptionTemplate, Task<Subscription?>> rebuildSubscription)
        {
            if (_options.ReconnectMaxRetries == 0)
            {
                ReconnectFailed?.Invoke();
                return false;
            }

            Task<bool>? pendingTask = null;
            lock (_lock)
            {
                if (_reconnecting && _pendingReconnect != null)
                {
                    pendingTask = _pendingReconnect.Task;
                }
                else
                {
                    _reconnecting = true;
                    _pendingReconnect = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            if (pendingTask != null)
            {

                return await pendingTask.ConfigureAwait(false);
            }

            _reconnectCts = new CancellationTokenSource();
            ReconnectStarted?.Invoke();

            var previousLogger = SecurityDebugLogger.Current;
            SecurityDebugLogger.SetCurrentLogger(_logger);
            bool success = false;
            try
            {
                var retries = 0;
                var delay = _options.ReconnectInitialDelayMs;

                while (_options.ReconnectMaxRetries < 0 || retries < _options.ReconnectMaxRetries)
                {
                    if (_reconnectCts.Token.IsCancellationRequested)
                        break;

                    try
                    {

                        await ConnectTransportAsync(endpointUrl).ConfigureAwait(false);

                        bool sessionRecovered = await RecoverSessionAsync(endpointUrl).ConfigureAwait(false);

                        bool lossless = await RecoverSubscriptionsAsync(sessionRecovered, rebuildSubscription).ConfigureAwait(false);

                        ReconnectCompleted?.Invoke(lossless);
                        success = true;
                        return true;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"Reconnect attempt {retries + 1} failed");

                        retries++;
                        if (_options.ReconnectMaxRetries >= 0 && retries >= _options.ReconnectMaxRetries)
                        {
                            _logger.LogError($"Reconnect: max retries ({_options.ReconnectMaxRetries}) exhausted");
                            ReconnectFailed?.Invoke();
                            return false;
                        }

                        ReconnectBackoff?.Invoke(retries, delay);
                        try { await Task.Delay(delay, _reconnectCts.Token); }
                        catch (OperationCanceledException) { break; }

                        delay = Math.Min(delay * 2, _options.ReconnectMaxDelayMs);
                    }
                }

                ReconnectFailed?.Invoke();
                return false;
            }
            finally
            {
                _reconnecting = false;
                _reconnectCts?.Dispose();
                _reconnectCts = null;
                var tcs = _pendingReconnect;
                _pendingReconnect = null;
                tcs?.TrySetResult(success);
                SecurityDebugLogger.SetCurrentLogger(previousLogger);
            }
        }

        private async Task ConnectTransportAsync(string endpointUrl)
        {
            var uri = new Uri(endpointUrl);
            await _connection.ConnectAsync(uri.Host, uri.Port).ConfigureAwait(false);
            await _connection.SendHelloAsync(endpointUrl, _options.MaxMessageSize).ConfigureAwait(false);

            var policy = _connection.SecurityPolicy;
            var nonce = new byte[policy.NonceLength];
            if (nonce.Length > 0)
                System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);

            await _connection.OpenSecureChannelAsync(new OpenSecureChannelParameters
            {
                RequestType = SecurityTokenRequestType.Issue,
                SecurityMode = policy.SecurityMode,
                ClientNonce = nonce.Length > 0 ? nonce : null,
                RequestedLifetime = _options.ChannelLifetime
            }).ConfigureAwait(false);
        }

        private async Task<bool> RecoverSessionAsync(string endpointUrl)
        {
            bool sessionRecovered = false;
            if (_lastSessionId != null && _lastAuthToken != null)
            {
                try
                {
                    await _connection.ActivateSessionAsync(_lastSessionId, _lastAuthToken, null ).ConfigureAwait(false);
                    sessionRecovered = true;
                    _logger.LogInformation("Reconnect: Session reactivated successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Reconnect: ActivateSession failed, will create new session");
                }
            }

            if (!sessionRecovered)
            {

                await _connection.CreateSessionAsync(endpointUrl, _options.ApplicationName,
                    _options.ApplicationUri, _options.ProductUri, (uint)_options.SessionTimeout).ConfigureAwait(false);
                await _connection.ActivateSessionAsync(null ).ConfigureAwait(false);
                _logger.LogInformation("Reconnect: New session created");
            }

            _lastSessionId = _connection.SessionId;
            _lastAuthToken = _connection.AuthenticationToken;

            return sessionRecovered;
        }

        private async Task<bool> RecoverSubscriptionsAsync(bool sessionRecovered, Func<SubscriptionTemplate, Task<Subscription?>> rebuildSubscription)
        {
            bool lossless = true;
            List<SubscriptionTemplate> templates;
            lock (_lock)
                templates = new List<SubscriptionTemplate>(_subscriptionTemplates);

            if (sessionRecovered && templates.Count > 0)
            {

                foreach (var tpl in templates)
                {
                    if (tpl.ActiveSubscription != null)
                        tpl.LastSequenceNumber = tpl.ActiveSubscription.LastSequenceNumber;
                }

                foreach (var tpl in templates)
                {
                    var sub = tpl.ActiveSubscription;
                    uint seq = tpl.LastSequenceNumber + 1;
                    int republishCount = 0;
                    const int maxRepublish = 1000;

                    while (republishCount < maxRepublish)
                    {
                        try
                        {
                            var msg = await _connection.RepublishAsync(tpl.SubscriptionId, seq).ConfigureAwait(false);

                            if (sub != null && sub._running)
                            {
                                sub.ProcessNotification(msg);
                            }

                            tpl.LastSequenceNumber = seq;
                            seq++;
                            republishCount++;
                        }
                        catch (UaException ex) when (ex.StatusCode == 0x803B0000)
                        {

                            break;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, $"Reconnect: Republish failed for sub {tpl.SubscriptionId} seq {seq}");
                            lossless = false;
                            break;
                        }
                    }

                    if (republishCount > 0)
                        _logger.LogDebug($"Reconnect: Republished {republishCount} notifications for sub {tpl.SubscriptionId}");
                }
            }
            else if (templates.Count > 0)
            {

                lossless = false;
                foreach (var tpl in templates)
                {
                    try
                    {
                        var sub = await rebuildSubscription(tpl).ConfigureAwait(false);
                        if (sub != null)
                        {
                            tpl.SubscriptionId = sub.SubscriptionId;
                            tpl.LastSequenceNumber = 0;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Reconnect: Failed to rebuild subscription");
                    }
                }
            }

            return lossless;
        }

        internal void CancelReconnect()
        {
            try { _reconnectCts?.Cancel(); } catch (ObjectDisposedException) { }
        }

        public void Dispose()
        {
            CancelReconnect();
        }

    }

    internal class SubscriptionTemplate
    {
        internal uint SubscriptionId { get; set; }
        internal uint LastSequenceNumber { get; set; }
        internal double PublishingInterval { get; set; } = 1000;
        internal uint LifetimeCount { get; set; } = 3600;
        internal uint MaxKeepAliveCount { get; set; } = 10;
        internal int MaxPublishRequests { get; set; } = 2;
        internal List<MonitoredItemTemplate> Items { get; set; } = new();

        internal Subscription? ActiveSubscription { get; set; }
    }

    internal class MonitoredItemTemplate
    {
        internal NodeId NodeId { get; set; } = new NodeId();
        internal AttributeId AttributeId { get; set; } = AttributeId.Value;
        internal double SamplingInterval { get; set; } = 1000;
        internal uint QueueSize { get; set; }
        internal uint ClientHandle { get; set; }
        internal DataChangeHandler? Handler { get; set; }
    }
}
