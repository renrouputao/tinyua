using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Core.Transport;
using TinyUa.Core.Client.Services;
using TinyUa.Core.Client.Connection;
using TinyUa.Core.Client.Subscriptions;
using TinyUa.Core.Security;
using TinyUa.Core.Security.Certificates;

namespace TinyUa.Core.Client
{
    public enum ClientState
    {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting,
        Reconnecting
    }

    public class UaClient : IAsyncDisposable
    {
        private readonly UaConnection _client;
        private readonly SubscriptionRouter _subscriptionRouter;
        private readonly UaClientOptions _options;
        private readonly ILogger _logger;
        private volatile string? _endpointUrl;
        private readonly object _lifecycleLock = new();
        private int _disposed;
        private volatile KeepAliveManager? _keepAliveManager;
        private volatile ReconnectEngine? _reconnectEngine;
        private volatile ClientState _state = ClientState.Disconnected;
        private readonly List<Subscription> _activeSubscriptions = new();
        private readonly object _subsLock = new();

        private readonly Dictionary<double, TaskCompletionSource<Subscription>> _pendingSubscriptionCreates = new();

        private TaskCompletionSource<bool>? _stopInProgress;

        public bool IsConnected => _state == ClientState.Connected && _client.IsAlive;
        public NodeId? SessionId => _client?.SessionId;
        public UaClientOptions Options => _options;
        public uint RevisedChannelLifetime => _client?.RevisedChannelLifetime ?? 0;
        public ClientState State => _state;

        private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        private void ThrowIfDisposed()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(UaClient));
        }

        public bool DebugMode
        {
            get => _debugMode;
            set
            {
                _debugMode = value;
                _client?.SetDebugMode(value);
            }
        }
        private bool _debugMode;

        public event Action<ClientState>? StateChanged;

        public event Action<bool>? SubscriptionsRecovered;

        public event Action<int, int>? ReconnectBackoff;

        public UaClient() : this(UaClientOptions.Default) { }

        public UaClient(string endpointUrl, UaClientOptions? options = null, ILogger? logger = null)
            : this(options ?? UaClientOptions.Default, logger)
        {
            _endpointUrl = endpointUrl ?? throw new ArgumentNullException(nameof(endpointUrl));
        }

        public UaClient(UaClientOptions options, ILogger? logger = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? NullLogger.Instance;
            _client = new UaConnection((int)options.Timeout, _logger);
            _subscriptionRouter = new SubscriptionRouter(_client);
        }

        public Task RunAsync() => RunAsync(CancellationToken.None);

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(_endpointUrl))
                throw new InvalidOperationException(
                    "No endpoint URL. Use new OpcUaClient(url) or OpcUaClient.ConnectTo(url).Build().");

            ThrowIfDisposed();

            lock (_lifecycleLock)
            {
                ThrowIfDisposed();
                if (_state == ClientState.Connected || _state == ClientState.Connecting) return;
                if (_state == ClientState.Disconnecting) return;
                SetStateUnderLock(ClientState.Connecting);
            }
            StateChanged?.Invoke(ClientState.Connecting);

            var retries = 0;
            var delay = _options.ReconnectInitialDelayMs;
            var maxRetries = _options.ReconnectMaxRetries;

            while (maxRetries < 0 || retries <= maxRetries)
            {
                try
                {
                    await ConnectInternalAsync(_endpointUrl).ConfigureAwait(false);

                    return;
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    SetState(ClientState.Disconnected);
                    try { await StopAsync().ConfigureAwait(false); } catch { }

                    retries++;
                    if (maxRetries >= 0 && retries > maxRetries)
                    {
                        if (_options.ErrorMode == ErrorMode.Throw)
                            throw new UaConnectionException(
                                $"Failed to connect to {_endpointUrl} after {retries} attempts", ex);
                        return;
                    }

                    lock (_lifecycleLock)
                    {
                        if (IsDisposed || _state == ClientState.Disconnecting) return;
                        SetStateUnderLock(ClientState.Connecting);
                    }
                    StateChanged?.Invoke(ClientState.Connecting);

                    _logger.LogWarning(ex, $"Connect attempt {retries} failed, retrying in {delay}ms");
                    try { await Task.Delay(delay, cancellationToken).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }
                    delay = Math.Min(delay * 2, _options.ReconnectMaxDelayMs);
                }
            }
        }

        private async Task ConnectInternalAsync(string endpointUrl)
        {
            _endpointUrl = endpointUrl;

            var previousLogger = SecurityDebugLogger.Current;
            SecurityDebugLogger.SetCurrentLogger(_logger);
            try
            {
                await ConnectInternalCoreAsync(endpointUrl).ConfigureAwait(false);
            }
            finally
            {
                SecurityDebugLogger.SetCurrentLogger(previousLogger);
            }
        }

        private async Task ConnectInternalCoreAsync(string endpointUrl)
        {
            var uri = new Uri(endpointUrl);
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : 4840;

            var security = _options.Security;
            var isSecure = SecurityPolicyFactory.IsSecurePolicy(security.Policy);

            X509Certificate2? localCert = null;
            if (isSecure)
            {
                localCert = LoadOrGenerateCertificate(security.Certificate);
                _logger.LogDebug($"Client certificate: {(localCert?.Thumbprint ?? "null")}");
            }

            X509Certificate2? remoteCert = null;
            var resolvedMode = security.Mode;
            string? userNamePolicyId = null;

            if (isSecure && security.AutoDiscoverServerCertificate)
            {
                _logger.LogDebug("Discovering server endpoints via GetEndpoints (None policy)...");
                var endpoints = await DiscoverEndpointsAsync(host, port, endpointUrl).ConfigureAwait(false);
                SecurityDebugLogger.LogStage("Connect.GetEndpoints",
                    ("endpointCount", endpoints?.Length ?? 0),
                    ("requestedPolicy", security.Policy),
                    ("requestedMode", security.Mode));
                var selected = SelectEndpoint(endpoints, security.Policy, security.Mode);
                if (selected == null)
                    throw new UaException(0x80000000,
                        $"No server endpoint matches policy '{security.Policy}' with mode '{security.Mode}'.");

                remoteCert = selected.ServerCertificateObject;
                resolvedMode = selected.SecurityMode;
                SecurityDebugLogger.LogStage("Connect.SelectEndpoint",
                    ("endpointUrl", selected.EndpointUrl),
                    ("securityMode", resolvedMode),
                    ("securityPolicyUri", selected.SecurityPolicyUri),
                    ("serverCertThumbprint", remoteCert?.Thumbprint),
                    ("securityLevel", selected.SecurityLevel));

                if (security.UserIdentity.Type == UserTokenType.UserName && selected.UserIdentityTokens != null)
                {
                    var userNamePolicy = selected.UserIdentityTokens
                        .FirstOrDefault(t => t.TokenType == UserTokenType.UserName);
                    userNamePolicyId = userNamePolicy?.PolicyId;
                }
            }

            var policy = SecurityPolicyFactory.Create(security.Policy, localCert, remoteCert, resolvedMode);
            _client.SetSecurityPolicy(policy);

            await _client.ConnectAsync(host, port).ConfigureAwait(false);
            await _client.SendHelloAsync(endpointUrl, _options.MaxMessageSize).ConfigureAwait(false);

            var clientNonce = new byte[policy.NonceLength];
            if (clientNonce.Length > 0)
                RandomNumberGenerator.Fill(clientNonce);

            await _client.OpenSecureChannelAsync(new OpenSecureChannelParameters
            {
                RequestType = SecurityTokenRequestType.Issue,
                SecurityMode = resolvedMode,
                ClientNonce = clientNonce.Length > 0 ? clientNonce : null,
                RequestedLifetime = _options.ChannelLifetime
            }).ConfigureAwait(false);

            var createResponse = await _client.CreateSessionAsync(endpointUrl, _options.ApplicationName,
                _options.ApplicationUri, _options.ProductUri, (uint)_options.SessionTimeout).ConfigureAwait(false);

            SecurityDebugLogger.LogStage("Connect.CreateSession",
                ("sessionId", createResponse.SessionId),
                ("serverNonceLen", createResponse.ServerNonce?.Length ?? -1),
                ("serverCertLen", createResponse.ServerCertificate?.Length ?? -1),
                ("serverSignatureAlg", createResponse.ServerSignature?.Algorithm),
                ("endpointsCount", createResponse.ServerEndpoints?.Length ?? 0));

            var identity = BuildUserIdentity(security.UserIdentity, createResponse, policy, userNamePolicyId);
            await _client.ActivateSessionAsync(identity).ConfigureAwait(false);

            _client.ConnectionLost += OnSocketConnectionLost;

            bool connectCompleted = false;
            lock (_lifecycleLock)
            {
                if (!IsDisposed && _state == ClientState.Connecting)
                {
                    SetStateUnderLock(ClientState.Connected);
                    connectCompleted = true;
                }
            }
            if (connectCompleted)
                StateChanged?.Invoke(ClientState.Connected);
            else
                return;

            StartKeepAlive();

            var sessionId = _client.SessionId;
            var authToken = new NodeId();
            _reconnectEngine = new ReconnectEngine(_client, _options, _logger);
            _reconnectEngine.ReconnectStarted += () => SetState(ClientState.Reconnecting);
            _reconnectEngine.ReconnectCompleted += (lossless) =>
            {
                SetState(ClientState.Connected);

                StartKeepAlive();
                SubscriptionsRecovered?.Invoke(lossless);
            };
            _reconnectEngine.ReconnectFailed += () => SetState(ClientState.Disconnected);
            _reconnectEngine.ReconnectBackoff += (retry, delay) => ReconnectBackoff?.Invoke(retry, delay);

            if (sessionId != null)
                _reconnectEngine.OnSessionEstablished(sessionId, authToken);

            await Task.CompletedTask;
        }

        private X509Certificate2? LoadOrGenerateCertificate(CertificateOptions certOptions)
        {
            if (!string.IsNullOrEmpty(certOptions.CertificatePath))
            {
                if (!string.IsNullOrEmpty(certOptions.PrivateKeyPath))
                {
                    var (cert, _) = CertificateLoader.LoadCertificateWithKey(
                        certOptions.CertificatePath!, certOptions.PrivateKeyPath!);
                    return cert;
                }
                return CertificateLoader.LoadCertificate(certOptions.CertificatePath!);
            }

            if (certOptions.AutoGenerate)
            {
                _logger.LogDebug($"Auto-generating self-signed certificate " +
                    $"(CN={_options.ApplicationName}, URI={_options.ApplicationUri})...");
                var (cert, _) = CertificateGenerator.CreateSelfSigned(
                    _options.ApplicationName,
                    _options.ApplicationUri,
                    certOptions.KeySize,
                    certOptions.ValidityYears);
                return cert;
            }

            return null;
        }

        private async Task<EndpointDescription[]?> DiscoverEndpointsAsync(string host, int port, string endpointUrl)
        {
            await _client.ConnectAsync(host, port).ConfigureAwait(false);
            try
            {
                await _client.SendHelloAsync(endpointUrl, _options.MaxMessageSize).ConfigureAwait(false);
                await _client.OpenSecureChannelAsync(new OpenSecureChannelParameters
                {
                    RequestType = SecurityTokenRequestType.Issue,
                    SecurityMode = MessageSecurityMode.None,
                    ClientNonce = null,
                    RequestedLifetime = 60000
                }).ConfigureAwait(false);

                return await _client.GetEndpointsAsync(endpointUrl).ConfigureAwait(false);
            }
            finally
            {
                await _client.DisconnectAsync().ConfigureAwait(false);
            }
        }

        private static EndpointDescription? SelectEndpoint(
            EndpointDescription[]? endpoints, string policyName, MessageSecurityMode mode)
        {
            if (endpoints == null || endpoints.Length == 0)
                return null;

            var policyUri = SecurityPolicyFactory.NormalizePolicyUri(policyName);
            var suffix = policyUri.Substring(policyUri.LastIndexOf('#'));

            var candidates = endpoints.Where(ep =>
                ep.SecurityPolicyUri != null
                && ep.SecurityPolicyUri.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                && ep.SecurityMode == mode);

            if (!candidates.Any())
            {
                candidates = endpoints.Where(ep =>
                    ep.SecurityPolicyUri != null
                    && ep.SecurityPolicyUri.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
            }

            return candidates.OrderByDescending(ep => ep.SecurityLevel).FirstOrDefault();
        }

        private static UserIdentityToken BuildUserIdentity(
            UserIdentityOptions identityOptions,
            CreateSessionResponse createResponse,
            SecurityPolicy policy,
            string? userNamePolicyId)
        {
            if (identityOptions.Type == UserTokenType.UserName)
            {
                return UserIdentityToken.CreateUserName(
                    identityOptions.Username ?? "",
                    identityOptions.Password ?? "",
                    userNamePolicyId,
                    createResponse.ServerNonce,
                    createResponse.ServerCertificate,
                    policy.Uri);
            }

            if (identityOptions.Type == UserTokenType.Certificate)
            {
                return new UserIdentityToken
                {
                    TokenType = UserTokenType.Certificate,
                    PolicyId = userNamePolicyId,
                    IssuedId = policy.SenderCertificate,
                    SecurityPolicyUri = policy.Uri
                };
            }

            return UserIdentityToken.Anonymous();
        }

        public Task StopAsync()
        {

            if (IsDisposed) return Task.CompletedTask;
            return StopAsyncCore();
        }

        private async Task StopAsyncCore()
        {
            TaskCompletionSource<bool>? waiter = null;
            bool iAmStopper;
            bool alreadyDisconnected = false;
            lock (_lifecycleLock)
            {
                if (_state == ClientState.Disconnected)
                {

                    alreadyDisconnected = true;
                    iAmStopper = false;
                }
                else if (_state == ClientState.Disconnecting)
                {

                    waiter = _stopInProgress;
                    iAmStopper = false;
                }
                else
                {
                    iAmStopper = true;
                    _stopInProgress = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    SetStateUnderLock(ClientState.Disconnecting);
                }
            }

            if (alreadyDisconnected)
            {
                StateChanged?.Invoke(ClientState.Disconnecting);
                StateChanged?.Invoke(ClientState.Disconnected);
                return;
            }

            if (!iAmStopper)
            {
                if (waiter != null)
                {
                    try { await waiter.Task.ConfigureAwait(false); } catch { }
                }
                return;
            }

            StateChanged?.Invoke(ClientState.Disconnecting);

            try
            {
                _reconnectEngine?.CancelReconnect();
                StopAndDisposeKeepAlive();

                Subscription[] subsToDispose;
                lock (_subsLock)
                {
                    subsToDispose = _activeSubscriptions.ToArray();
                    _activeSubscriptions.Clear();

                    foreach (var kvp in _pendingSubscriptionCreates)
                        kvp.Value.TrySetException(new ObjectDisposedException(nameof(UaClient)));
                    _pendingSubscriptionCreates.Clear();
                }
                foreach (var sub in subsToDispose)
                {
                    try { sub.Dispose(); } catch { }
                }

                try { await _client!.CloseSessionAsync().ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "CloseSession error during stop (ignored)"); }
                try { await _client.CloseSecureChannelAsync().ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "CloseSecureChannel error during stop (ignored)"); }
                try { await _client.DisconnectAsync().ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "Disconnect error during stop (ignored)"); }
            }
            finally
            {
                lock (_lifecycleLock)
                    SetStateUnderLock(ClientState.Disconnected);
                StateChanged?.Invoke(ClientState.Disconnected);

                var tcs = _stopInProgress;
                _stopInProgress = null;
                tcs?.TrySetResult(true);
            }
        }

        private void StopAndDisposeKeepAlive()
        {
            if (_keepAliveManager == null) return;
            _keepAliveManager?.Stop();
            _keepAliveManager?.Dispose();
            _keepAliveManager = null;
        }

        private void StartKeepAlive()
        {
            StopAndDisposeKeepAlive();
            _keepAliveManager = new KeepAliveManager(_client, (int)_options.SessionTimeout, (int)_options.ChannelLifetime, _logger);
            _keepAliveManager.Start();
        }

        private void OnSocketConnectionLost(Exception? ex)
        {

            var actualEx = ex ?? new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionReset);
            OnConnectionLostAsync(actualEx).Forget(_logger, nameof(OnConnectionLostAsync));
        }

        private async Task OnConnectionLostAsync(Exception ex)
        {
            _logger.LogWarning(ex, "Connection lost — triggering reconnect");

            ReconnectEngine? engine;
            string? endpointUrl;
            Subscription[] activeSubs;

            lock (_lifecycleLock)
            {

                if (IsDisposed
                    || _state == ClientState.Disconnecting
                    || _state == ClientState.Disconnected)
                    return;

                SetStateUnderLock(ClientState.Reconnecting);
                engine = _reconnectEngine;
                endpointUrl = _endpointUrl;
            }
            StateChanged?.Invoke(ClientState.Reconnecting);

            StopAndDisposeKeepAlive();

            lock (_subsLock)
                activeSubs = _activeSubscriptions.ToArray();
            foreach (var sub in activeSubs)
            {
                try { sub.StopPublishing(); } catch { }
            }

            if (engine != null && endpointUrl != null)
            {
                await engine.ReconnectAsync(endpointUrl, RebuildSubscriptionAsync);
            }
        }

        private async Task<Subscription?> RebuildSubscriptionAsync(SubscriptionTemplate template)
        {

            var oldSub = template.ActiveSubscription;
            if (oldSub != null)
            {
                oldSub.StopPublishing();
                try { oldSub.Dispose(); } catch { }
                lock (_subsLock)
                    _activeSubscriptions.Remove(oldSub);
            }

            var sub = await SubscriptionManager.CreateSubscriptionAsync(
                _subscriptionRouter,
                template.PublishingInterval,
                autoStart: true,
                template.MaxPublishRequests,
                _logger).ConfigureAwait(false);

            template.SubscriptionId = sub.SubscriptionId;
            template.ActiveSubscription = sub;

            lock (_subsLock)
                _activeSubscriptions.Add(sub);

            foreach (var item in template.Items)
            {
                await sub.AddMonitoredItemAsync(item.NodeId, item.SamplingInterval, item.Handler, item.QueueSize).ConfigureAwait(false);
            }

            return sub;
        }

        private ClientState SetStateUnderLock(ClientState state)
        {
            _state = state;
            return state;
        }

        private void SetState(ClientState state)
        {
            ClientState captured;
            lock (_lifecycleLock)
                captured = SetStateUnderLock(state);
            StateChanged?.Invoke(captured);
        }

        private async Task EnsureConnectedAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_state == ClientState.Connected && _client.IsAlive)
                return;

            ReconnectEngine? engine;
            string? endpointUrl;
            bool iTriggeredReconnect = false;

            lock (_lifecycleLock)
            {
                ThrowIfDisposed();
                if (_state != ClientState.Reconnecting
                    && _state != ClientState.Connecting
                    && _state != ClientState.Disconnecting
                    && _state != ClientState.Disconnected)
                {
                    _logger.LogWarning($"EnsureConnectedAsync: connection dead (state={_state}, alive={_client.IsAlive}) — triggering reconnect");
                    SetStateUnderLock(ClientState.Reconnecting);
                    iTriggeredReconnect = true;
                }
                engine = _reconnectEngine;
                endpointUrl = _endpointUrl;
            }
            if (iTriggeredReconnect)
                StateChanged?.Invoke(ClientState.Reconnecting);

            if (engine == null || string.IsNullOrEmpty(endpointUrl))
                throw new UaConnectionException("Client is not connected. Call RunAsync() first.");

            var success = await engine.ReconnectAsync(endpointUrl, RebuildSubscriptionAsync)
                .WithTimeout((int)_options.Timeout, "Timed out waiting for reconnection")
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            if (success)
            {

                return;
            }
            throw new UaConnectionException($"Reconnect failed after max retries ({_options.ReconnectMaxRetries})");
        }

        private static bool IsConnectionError(Exception ex)
        {
            if (ex is System.Net.Sockets.SocketException) return true;
            if (ex is System.IO.IOException) return true;
            if (ex is UaException ua)
            {

                uint code = ua.StatusCode & 0xC0000000;
                return code == 0x80000000;
            }
            return false;
        }

        private async Task<T?> ExecuteWithRetryAsync<T>(string operationName, Func<Task<T?>> operation, CancellationToken cancellationToken = default) where T : class
        {
            for (int attempt = 0; ; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
                    return await operation().ConfigureAwait(false);
                }
                catch (TimeoutException ex)
                {

                    _logger.LogWarning(ex, $"{operationName} timed out waiting for reconnection");
                    SetState(ClientState.Reconnecting);
                    if (_options.ErrorMode == ErrorMode.Throw)
                        throw new UaConnectionException($"{operationName} timed out waiting for reconnection");
                    return null;
                }
                catch (Exception ex) when (attempt == 0 && IsConnectionError(ex))
                {
                    _logger.LogWarning(ex, $"{operationName} failed with connection error — reconnecting and retrying");
                    SetState(ClientState.Reconnecting);
                    continue;
                }
                catch (Exception ex)
                {
                    if (_options.ErrorMode == ErrorMode.Throw)
                        throw new UaOperationException($"{operationName} failed", ex);
                    return null;
                }
            }
        }

        public async Task<DataValue?> ReadAsync(NodeId nodeId, AttributeId attributeId = AttributeId.Value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeId, attributeId), cancellationToken).ConfigureAwait(false);
            return results != null && results.Length > 0 ? results[0] : null;
        }

        public async Task<DataValue[]?> ReadAsync(NodeId[] nodeIds, AttributeId attributeId = AttributeId.Value, CancellationToken cancellationToken = default)
        {
            if (nodeIds == null) throw new ArgumentNullException(nameof(nodeIds));
            if (nodeIds.Length == 0) throw new ArgumentException("NodeIds array cannot be empty", nameof(nodeIds));
            return await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeIds, attributeId), cancellationToken).ConfigureAwait(false);
        }

        public async Task<T?> ReadValueAsync<T>(NodeId nodeId, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await ReadAsync(nodeId, AttributeId.Value, cancellationToken).ConfigureAwait(false);
            return ExtractValue<T>(results);
        }

        public async Task<T?> ReadValueAsync<T>(NodeId nodeId, AttributeId attributeId, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await ReadAsync(nodeId, attributeId, cancellationToken).ConfigureAwait(false);
            return ExtractValue<T>(results);
        }

        private static T? ExtractValue<T>(DataValue? result)
        {
            if (result?.Value?.Value != null)
            {
                try { return (T?)result.Value.Value; }
                catch (InvalidCastException) { return default; }
            }
            return default;
        }

        public async Task<T?> ReadValueAsync<T>(string nodeIdString, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            var nodeId = ParseNodeId(nodeIdString);
            return await ReadValueAsync<T>(nodeId, cancellationToken).ConfigureAwait(false);
        }

        public async Task<StatusCode?> WriteAsync(NodeId nodeId, object value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await ExecuteWithRetryAsync("Write", () => _client!.WriteAsync(nodeId, value), cancellationToken).ConfigureAwait(false);
            return results != null && results.Length > 0 ? results[0] : null;
        }

        public async Task<StatusCode[]?> WriteAsync(WriteValue[] values, CancellationToken cancellationToken = default)
        {
            if (values == null) throw new ArgumentNullException(nameof(values));
            if (values.Length == 0) throw new ArgumentException("WriteValues array cannot be empty", nameof(values));
            return await ExecuteWithRetryAsync("Write", () => _client!.WriteAsync(values), cancellationToken).ConfigureAwait(false);
        }

        public Task<StatusCode?> WriteAsync(string nodeIdString, object value, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            return WriteAsync(ParseNodeId(nodeIdString), value, cancellationToken);
        }

        public async Task WriteValueAsync<T>(NodeId nodeId, T value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            await WriteAsync(nodeId, value!, cancellationToken).ConfigureAwait(false);
        }

        public async Task WriteValueAsync<T>(string nodeIdString, T value, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            var nodeId = ParseNodeId(nodeIdString);
            await WriteAsync(nodeId, value!, cancellationToken).ConfigureAwait(false);
        }

        public async Task<BrowseResult[]?> BrowseAsync(NodeId nodeId, BrowseDirection direction = BrowseDirection.Forward, uint maxReferences = 100, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            return await ExecuteWithRetryAsync("Browse", () => _client!.BrowseAsync(nodeId, direction, maxReferences), cancellationToken).ConfigureAwait(false);
        }

        public async Task<BrowseResult[]?> BrowseNextAsync(byte[] continuationPoint, CancellationToken cancellationToken = default)
        {
            if (continuationPoint == null) throw new ArgumentNullException(nameof(continuationPoint));
            return await ExecuteWithRetryAsync("BrowseNext", () => _client!.BrowseNextAsync(continuationPoint), cancellationToken).ConfigureAwait(false);
        }

        private async Task<Subscription> GetOrCreateDefaultSubscriptionAsync(double interval, CancellationToken cancellationToken = default)
        {
            TaskCompletionSource<Subscription>? pending;
            bool iAmCreator;

            lock (_subsLock)
            {

                foreach (var sub in _activeSubscriptions)
                {
                    if (Math.Abs(sub.PublishingInterval - interval) < 0.001)
                        return sub;
                }

                if (_pendingSubscriptionCreates.TryGetValue(interval, out pending))
                {
                    iAmCreator = false;
                }
                else
                {
                    iAmCreator = true;
                    pending = new TaskCompletionSource<Subscription>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingSubscriptionCreates[interval] = pending;
                }
            }

            if (!iAmCreator)
                return await pending!.Task.ConfigureAwait(false);

            try
            {
                var sub = await CreateSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
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
                lock (_subsLock)
                    _pendingSubscriptionCreates.Remove(interval);
            }
        }

        public async Task<Subscription> CreateSubscriptionAsync(double publishingInterval = 1000.0, CancellationToken cancellationToken = default)
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);

            var result = await _subscriptionRouter.CreateSubscriptionAsync(publishingInterval).ConfigureAwait(false);
            var sub = new Subscription(
                _subscriptionRouter,
                result.SubscriptionId,
                result.RevisedPublishingInterval,
                result.RevisedLifetimeCount,
                result.RevisedMaxKeepAliveCount,
                maxPublishRequests: 2,
                _logger);
            sub.StartPublishing();

            var template = new SubscriptionTemplate
            {
                SubscriptionId = sub.SubscriptionId,
                PublishingInterval = publishingInterval,
                LifetimeCount = sub.LifetimeCount,
                MaxKeepAliveCount = sub.MaxKeepAliveCount
            };
            _reconnectEngine?.RegisterSubscription(template, sub);

            lock (_subsLock)
                _activeSubscriptions.Add(sub);

            return sub;
        }

        public async Task DeleteSubscriptionAsync(Subscription subscription, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            _reconnectEngine?.UnregisterSubscription(subscription.SubscriptionId);
            lock (_subsLock)
                _activeSubscriptions.Remove(subscription);
            await subscription.DeleteAsync().ConfigureAwait(false);
        }

        public async Task<StatusCode[]> DeleteMonitoredItemsAsync(Subscription subscription, uint[] monitoredItemIds, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            return await subscription.DeleteMonitoredItemsAsync(monitoredItemIds).ConfigureAwait(false);
        }

        public async Task<(Subscription Subscription, uint MonitoredItemId)> SubscribeAsync(
            NodeId nodeId, DataChangeHandler handler, double interval = 1000.0, uint queueSize = 0,
            CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            var item = await sub.AddMonitoredItemAsync(nodeId, handler, queueSize).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, queueSize, handler);
            return (sub, item.MonitoredItemId);
        }

        public async Task<Subscription> SubscribeAsync(NodeId[] nodeIds, DataChangeHandler handler, double interval = 1000.0, uint queueSize = 0, CancellationToken cancellationToken = default)
        {
            if (nodeIds == null) throw new ArgumentNullException(nameof(nodeIds));
            if (nodeIds.Length == 0) throw new ArgumentException("NodeIds array cannot be empty", nameof(nodeIds));
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < nodeIds.Length; i++)
            {
                await sub.AddMonitoredItemAsync(nodeIds[i], handler, queueSize).ConfigureAwait(false);
                UpdateTemplate(sub, nodeIds[i], interval, queueSize, handler);
            }
            return sub;
        }

        private void UpdateTemplate(Subscription sub, NodeId nodeId, double samplingInterval, uint queueSize, DataChangeHandler? handler)
        {

            _reconnectEngine?.RegisterSubscription(new SubscriptionTemplate
            {
                SubscriptionId = sub.SubscriptionId,
                PublishingInterval = sub.PublishingInterval,
                LifetimeCount = sub.LifetimeCount,
                MaxKeepAliveCount = sub.MaxKeepAliveCount,
                Items = new System.Collections.Generic.List<MonitoredItemTemplate>
                {
                    new MonitoredItemTemplate
                    {
                        NodeId = nodeId,
                        SamplingInterval = samplingInterval,
                        QueueSize = queueSize,
                        Handler = handler
                    }
                }
            }, sub);
        }

        public static NodeId ParseNodeId(string nodeIdString)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));

            if (nodeIdString.StartsWith("s="))
            {
                var parts = nodeIdString.Substring(2).Split(new[] { ';' }, 2);
                if (parts.Length == 2 && parts[0].StartsWith("ns="))
                {
                    try
                    {
                        var ns = ushort.Parse(parts[0].Substring(3));
                        return new NodeId(parts[1], ns);
                    }
                    catch { }
                }
            }

            try
            {
                return NodeId.Parse(nodeIdString);
            }
            catch (FormatException)
            {

                if (nodeIdString.StartsWith("ns=") && !nodeIdString.Contains(';'))
                {
                    return new NodeId(nodeIdString, 0);
                }
                throw new ArgumentException($"Invalid NodeId format: {nodeIdString}", nameof(nodeIdString));
            }
        }

        public async ValueTask DisposeAsync()
        {

            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

            try { await StopAsyncCore().ConfigureAwait(false); } catch { }
            try { _reconnectEngine?.Dispose(); } catch { }
            try { _client?.Dispose(); } catch { }
            GC.SuppressFinalize(this);
        }

        public async Task<Subscription> SubscribeAsync<T>(
            string nodeIdString,
            Action<T?> onDataChanged,
            double interval = 1000.0,
            CancellationToken cancellationToken = default)
        {
            var nodeId = NodeId.Parse(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (handle, value, status) =>
            {
                if (status.IsGood && value is T typed)
                    onDataChanged(typed);
                else
                    onDataChanged(default);
            };
            await sub.AddMonitoredItemAsync(nodeId, handler).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, 0, handler);
            return sub;
        }

        public async Task<Subscription> SubscribeAsync<T>(
            string nodeIdString,
            Action<T?, StatusCode> onDataChanged,
            double interval = 1000.0,
            CancellationToken cancellationToken = default)
        {
            var nodeId = NodeId.Parse(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (handle, value, status) =>
            {
                if (status.IsGood && value is T typed)
                    onDataChanged(typed, status);
                else
                    onDataChanged(default, status);
            };
            await sub.AddMonitoredItemAsync(nodeId, handler).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, 0, handler);
            return sub;
        }

        public static ClientBuilder ConnectTo(string endpointUrl)
            => new ClientBuilder(endpointUrl);

        public static ClientBuilder ConnectTo(Uri endpointUri)
            => new ClientBuilder(endpointUri.ToString());

        public class ClientBuilder
        {
            private readonly string _endpointUrl;

            private readonly UaClientOptions _options = UaClientOptions.Default;
            private bool _reconnect = true;
            private ILogger? _logger;

            internal ClientBuilder(string endpointUrl) { _endpointUrl = endpointUrl; }

            public ClientBuilder WithRequestTimeout(int milliseconds) { _options.Timeout = (uint)milliseconds; return this; }
            public ClientBuilder WithAppName(string name) { _options.ApplicationName = name; _options.ApplicationUri = $"urn:{name}:{Guid.NewGuid()}"; return this; }
            public ClientBuilder WithoutReconnect() { _reconnect = false; return this; }
            public ClientBuilder WithReconnectRetries(int maxRetries) { _options.ReconnectMaxRetries = maxRetries; return this; }
            public ClientBuilder WithSessionTimeout(int ms) { _options.SessionTimeout = ms; return this; }
            public ClientBuilder WithErrorMode(ErrorMode mode) { _options.ErrorMode = mode; return this; }

            public ClientBuilder WithSecurity(string policy)
            {
                _options.Security.Policy = policy;
                if (policy != "None")
                    _options.Security.Mode = TinyUa.Core.Security.MessageSecurityMode.SignAndEncrypt;
                return this;
            }

            public ClientBuilder WithSecurity(Action<SecurityOptions> configure)
            {
                configure(_options.Security);
                return this;
            }

            public ClientBuilder WithUserName(string username, string password)
            {
                _options.Security.UserIdentity.Type = TinyUa.Core.Security.UserTokenType.UserName;
                _options.Security.UserIdentity.Username = username;
                _options.Security.UserIdentity.Password = password;
                return this;
            }

            public ClientBuilder WithLogger(ILogger logger) { _logger = logger; return this; }

            public ClientBuilder EnableLog(Action<LogLevel, Exception?, string> sink, LogLevel minLevel = LogLevel.Debug)
            {
                _logger = new DelegateLogger(sink, minLevel);
                return this;
            }

            public ClientBuilder EnableLogFile(string directory, LogLevel minLevel = LogLevel.Debug, bool async = false)
            {
                _logger = new FileLogger(directory, minLevel, async);
                return this;
            }

            public UaClient Build()
            {
                _options.ReconnectMaxRetries = _reconnect ? _options.ReconnectMaxRetries : 0;
                var client = new UaClient(_options, _logger);
                client._endpointUrl = _endpointUrl;
                return client;
            }

            public async Task<UaClient> BuildAndRunAsync()
            {
                var client = Build();
                await client.RunAsync().ConfigureAwait(false);
                return client;
            }
        }
    }
}
