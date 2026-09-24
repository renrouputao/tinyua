using TinyUa.Core;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Client.Security;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;
using TinyUa.Transport;
using TinyUa.Core.Security;

namespace TinyUa.Client.Connection
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
        private bool _stopped;

        private NodeId? _lastSessionId;
        private NodeId? _lastAuthToken;

        internal bool IsReconnecting => _reconnecting;

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
                    // Dedup by ClientHandle, not NodeId: the same node may legitimately be
                    // monitored twice with different handlers/settings, and each monitored item
                    // gets a unique client handle. Deduping by NodeId silently dropped the second
                    // handler from the rebuild template.
                    foreach (var item in template.Items)
                    {
                        if (!existing.Items.Any(i => i.ClientHandle == item.ClientHandle))
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

        internal void UnregisterSubscription(Subscription subscription)
        {
            lock (_lock) _subscriptionTemplates.RemoveAll(t => ReferenceEquals(t.ActiveSubscription, subscription));
        }

        internal async Task<bool> ReconnectAsync(string endpointUrl, Func<SubscriptionTemplate, Task<Subscription?>> rebuildSubscription)
        {
            if (_options.ReconnectMaxRetries == 0)
            {
                ReconnectFailed?.Invoke();
                return false;
            }

            Task<bool>? pendingTask = null;
            CancellationTokenSource reconnectCts;
            TaskCompletionSource<bool> completion;
            lock (_lock)
            {
                if (_stopped) return false;
                if (_pendingReconnect != null)
                {
                    pendingTask = _pendingReconnect.Task;
                    reconnectCts = _reconnectCts!;
                    completion = _pendingReconnect;
                }
                else
                {
                    _reconnecting = true;
                    reconnectCts = _reconnectCts = new CancellationTokenSource();
                    completion = _pendingReconnect = new(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }
            if (pendingTask != null) return await pendingTask.ConfigureAwait(false);
            var cancellationToken = reconnectCts.Token;
            using var loggerScope = SecurityDebugLogger.BeginScope(_logger);
            bool success = false;
            try
            {
                var retries = 0;
                var backoff = new BackoffPolicy(_options.ReconnectInitialDelayMs, _options.ReconnectMaxDelayMs, jitter: true);

                while (_options.ReconnectMaxRetries < 0 || retries < _options.ReconnectMaxRetries)
                {
                    if (reconnectCts.Token.IsCancellationRequested)
                        break;

                    try
                    {

                        await ConnectTransportAsync(endpointUrl, cancellationToken).ConfigureAwait(false);

                        bool sessionRecovered = await RecoverSessionAsync(endpointUrl, cancellationToken).ConfigureAwait(false);

                        bool lossless = await RecoverSubscriptionsAsync(sessionRecovered, rebuildSubscription, cancellationToken).ConfigureAwait(false);

                        cancellationToken.ThrowIfCancellationRequested();
                        ReconnectCompleted?.Invoke(lossless);
                        success = true;
                        return true;
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
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

                        var delay = backoff.NextDelay();
                        ReconnectBackoff?.Invoke(retries, delay);
                        try { await Task.Delay(delay, reconnectCts.Token); }
                        catch (OperationCanceledException) { break; }
                    }
                }

                if (!cancellationToken.IsCancellationRequested) ReconnectFailed?.Invoke();
                return false;
            }
            finally
            {
                if (!success)
                {
                    // A cancelled handshake cannot carry graceful session-close traffic.
                    // Close it before completing StopAsync so shutdown never waits on the peer.
                    try { await _connection.DisconnectAsync().ConfigureAwait(false); } catch { }
                }
                lock (_lock)
                {
                    _reconnecting = false;
                    _reconnectCts = null;
                    _pendingReconnect = null;
                    completion.TrySetResult(success);
                }
                reconnectCts.Dispose();
            }
        }

        private async Task ConnectTransportAsync(string endpointUrl, CancellationToken cancellationToken)
        {
            var uri = new Uri(endpointUrl);
            // Uri.Port is -1 when an opc.tcp URL omits its port. Initial connection
            // normalizes this to the OPC UA default (4840); reconnect must do the same.
            await _connection.ConnectAsync(uri.Host, ResolvePort(uri), cancellationToken).ConfigureAwait(false);
            await _connection.SendHelloAsync(endpointUrl, _options.MaxMessageSize, cancellationToken).ConfigureAwait(false);

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
            }, cancellationToken).ConfigureAwait(false);
        }

        private async Task<bool> RecoverSessionAsync(string endpointUrl, CancellationToken cancellationToken)
        {
            bool sessionRecovered = false;
            if (_lastSessionId != null && _lastAuthToken != null)
            {
                try
                {
                    var identity = _connection.BuildIdentity(_options.Security.UserIdentity, endpointUrl);
                    await _connection.ActivateSessionAsync(_lastSessionId, _lastAuthToken, identity, cancellationToken).ConfigureAwait(false);
                    sessionRecovered = true;
                    _logger.LogInformation("Reconnect: Session reactivated successfully");
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    _logger.LogDebug(ex, "Reconnect: ActivateSession failed, will create new session");
                }
            }

            if (!sessionRecovered)
            {

                var createResponse = await _connection.CreateSessionAsync(endpointUrl, _options.ApplicationName,
                    _options.ApplicationUri, _options.ProductUri, (uint)_options.SessionTimeout, cancellationToken).ConfigureAwait(false);
                var identity = UserIdentityFactory.Build(
                    _options.Security.UserIdentity, createResponse, _connection.SecurityPolicy,
                    _connection.UserTokenPolicyId, endpointUrl);
                _connection.UserTokenPolicyId = identity.PolicyId;
                await _connection.ActivateSessionAsync(identity, cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("Reconnect: New session created");
            }

            _lastSessionId = _connection.SessionId;
            _lastAuthToken = _connection.AuthenticationToken;

            return sessionRecovered;
        }

        private async Task<bool> RecoverSubscriptionsAsync(bool sessionRecovered, Func<SubscriptionTemplate, Task<Subscription?>> rebuildSubscription, CancellationToken cancellationToken)
        {
            bool lossless = true;
            List<SubscriptionTemplate> templates;
            lock (_lock)
                templates = new List<SubscriptionTemplate>(_subscriptionTemplates);

            if (sessionRecovered && templates.Count > 0)
            {

                foreach (var tpl in templates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (tpl.ActiveSubscription?.IsSubscriptionDisposed == true) continue;
                    if (tpl.ActiveSubscription != null)
                        tpl.LastSequenceNumber = tpl.ActiveSubscription.LastSequenceNumber;
                }

                foreach (var tpl in templates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (tpl.ActiveSubscription?.IsSubscriptionDisposed == true) continue;
                    var sub = tpl.ActiveSubscription;
                    uint seq = tpl.LastSequenceNumber == uint.MaxValue ? 1 : tpl.LastSequenceNumber + 1;
                    int republishCount = 0;
                    const int maxRepublish = 1000;

                    while (republishCount < maxRepublish)
                    {
                        try
                        {
                            var msg = await _connection.RepublishAsync(tpl.SubscriptionId, seq, cancellationToken).ConfigureAwait(false);

                            // Publishing is stopped during a connection loss, so gate on disposal,
                            // not on _running — otherwise every republished notification of a
                            // lossless recovery would be dropped silently.
                            if (sub != null && !sub.IsSubscriptionDisposed)
                            {
                                // Preserve the same bounded, serial dispatch path as live
                                // Publish responses. Processing republished data inline used to
                                // bypass backpressure and left LastSequenceNumber stale.
                                await sub.EnqueueRepublishAsync(msg, cancellationToken).ConfigureAwait(false);
                            }

                            tpl.LastSequenceNumber = seq;
                            seq = seq == uint.MaxValue ? 1 : seq + 1;
                            republishCount++;
                        }
                        catch (UaException ex) when (ex.StatusCode == 0x807B0000)
                        {

                            break;
                        }
                        catch (UaException ex) when (ex.StatusCode == 0x80280000)
                        {
                            lossless = false;
                            tpl.CancellationToken = cancellationToken;
                            var rebuilt = await rebuildSubscription(tpl).ConfigureAwait(false);
                            if (rebuilt != null) tpl.SubscriptionId = rebuilt.SubscriptionId;
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
                    if (republishCount == maxRepublish) lossless = false;
                }
            }
            else if (templates.Count > 0)
            {

                lossless = false;
                foreach (var tpl in templates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (tpl.ActiveSubscription?.IsSubscriptionDisposed == true) continue;
                    try
                    {
                        tpl.CancellationToken = cancellationToken;
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
                        // The next attempt must rebuild all remaining subscriptions again.
                        _lastSessionId = null;
                        _lastAuthToken = null;
                        throw;
                    }
                }
            }

            return lossless;
        }

        internal static int ResolvePort(Uri endpointUri)
        {
            if (endpointUri == null) throw new ArgumentNullException(nameof(endpointUri));
            return endpointUri.Port > 0 ? endpointUri.Port : 4840;
        }

        internal void CancelReconnect()
        {
            lock (_lock)
            {
                _stopped = true;
                try { _reconnectCts?.Cancel(); } catch (ObjectDisposedException) { }
            }
        }

        internal async Task StopAsync()
        {
            CancelReconnect();
            Task? pending;
            lock (_lock) pending = _pendingReconnect?.Task;
            if (pending != null) await pending.ConfigureAwait(false);
        }

        public void Dispose()
        {
            CancelReconnect();
        }

    }

    internal class SubscriptionTemplate
    {
        internal CancellationToken CancellationToken { get; set; }
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
        internal DataChangeHandlerEx? HandlerEx { get; set; }
    }
}
