using TinyUa.Core;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Transport;
using TinyUa.Client.Services;
using TinyUa.Client.Connection;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Security;
using TinyUa.Core.Security.Certificates;

namespace TinyUa.Client
{
    /// <summary>Client connection state.</summary>
    public enum ClientState
    {
        /// <summary>Not connected (initial state, or after disconnect).</summary>
        Disconnected,
        /// <summary>Connection in progress.</summary>
        Connecting,
        /// <summary>Connected and ready for read/write operations.</summary>
        Connected,
        /// <summary>Disconnection in progress.</summary>
        Disconnecting,
        /// <summary>Connection lost, automatic reconnection in progress.</summary>
        Reconnecting
    }

    /// <summary>
    /// TinyUa OPC UA client.
    /// All operations (Read/Write/Browse/Subscribe) include automatic reconnect and timeout handling.
    /// Implements <see cref="IAsyncDisposable"/> — use <c>await using var client = ...</c> for proper cleanup.
    /// </summary>
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

        /// <summary>Whether the client is currently connected and the underlying channel is alive.</summary>
        public bool IsConnected => _state == ClientState.Connected && _client.IsAlive;

        /// <summary>The session ID assigned by the server after a successful connection.</summary>
        public NodeId? SessionId => _client?.SessionId;

        /// <summary>The configuration copy used at creation time (runtime changes have no effect).</summary>
        public UaClientOptions Options => _options;

        /// <summary>The actual channel lifetime negotiated with the server (milliseconds).</summary>
        public uint RevisedChannelLifetime => _client?.RevisedChannelLifetime ?? 0;

        /// <summary>Current client connection state.</summary>
        public ClientState State => _state;

        private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        private void ThrowIfDisposed()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(UaClient));
        }

        /// <summary>
        /// Enable debug mode to print detailed secure channel handshake information to the console.
        /// </summary>
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

        /// <summary>Raised when the connection state changes. Argument is the new <see cref="ClientState"/>.</summary>
        public event Action<ClientState>? StateChanged;

        /// <summary>
        /// Raised when subscriptions are recovered after reconnect.
        /// Argument is <c>true</c> for lossless recovery (no data lost), <c>false</c> if subscriptions were rebuilt with potential data loss.
        /// </summary>
        public event Action<bool>? SubscriptionsRecovered;

        /// <summary>
        /// Raised during reconnect backoff, useful for monitoring/logging.
        /// Arguments are (current retry count, current backoff delay in ms).
        /// </summary>
        public event Action<int, int>? ReconnectBackoff;

        /// <summary>Create a client with default options. URL must be set before calling <see cref="RunAsync()"/>.</summary>
        public UaClient() : this(UaClientOptions.Default) { }

        /// <summary>Create a client with a URL and default options. Prefer <see cref="ConnectTo(string)"/> for fluent configuration.</summary>
        /// <param name="endpointUrl">OPC UA server URL, e.g. <c>opc.tcp://localhost:4840</c>.</param>
        /// <param name="options">Optional configuration overrides.</param>
        /// <param name="logger">Optional logger.</param>
        public UaClient(string endpointUrl, UaClientOptions? options = null, ILogger? logger = null)
            : this(options ?? UaClientOptions.Default, logger)
        {
            _endpointUrl = endpointUrl ?? throw new ArgumentNullException(nameof(endpointUrl));
        }

        /// <summary>Create a client with explicit options. URL must be set in the <c>ConnectTo(url)</c> step.</summary>
        /// <param name="options">Client configuration. Must not be <c>null</c>.</param>
        /// <param name="logger">Optional logger.</param>
        public UaClient(UaClientOptions options, ILogger? logger = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? NullLogger.Instance;
            _client = new UaConnection((int)options.Timeout, _logger);
            _subscriptionRouter = new SubscriptionRouter(_client);
        }

        /// <summary>Start connection without cancellation. Performs full handshake: Hello → OpenChannel → CreateSession → ActivateSession.</summary>
        public Task RunAsync() => RunAsync(CancellationToken.None);

        /// <summary>
        /// Start connection with full handshake. If reconnect is enabled (default), will not return failure
        /// until all retries are exhausted. State transitions to <see cref="ClientState.Connected"/> on success.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the connection attempt.</param>
        /// <exception cref="InvalidOperationException">No endpoint URL has been set.</exception>
        /// <exception cref="ObjectDisposedException">Client has been disposed.</exception>
        /// <exception cref="UaConnectionException">All reconnect attempts failed.</exception>
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
            string? userTokenPolicyId = null;
            EndpointDescription? selected = null;

            if (isSecure && security.AutoDiscoverServerCertificate)
            {
                _logger.LogDebug("Discovering server endpoints via GetEndpoints (None policy)...");
                var endpoints = await DiscoverEndpointsAsync(host, port, endpointUrl).ConfigureAwait(false);
                SecurityDebugLogger.LogStage("Connect.GetEndpoints",
                    ("endpointCount", endpoints?.Length ?? 0),
                    ("requestedPolicy", security.Policy),
                    ("requestedMode", security.Mode));
                selected = SelectEndpoint(endpoints, security.Policy, security.Mode);
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

                // Validate the discovered server certificate unless the caller opted into
                // auto-trust. Without this, AutoAcceptServerCertificate=false had no effect.
                if (!security.AutoAcceptServerCertificate)
                {
                    var validator = new CertificateValidator();
                    try
                    {
                        validator.Validate(remoteCert, isServerCertificate: true);
                    }
                    catch (Exception ex)
                    {
                        throw new UaException(0x80120000,
                            $"Server certificate validation failed: {ex.Message}");
                    }
                }

                // Resolve the server's PolicyId for the configured user token type (UserName or
                // Certificate). Anonymous needs no policy id. Matching by TokenType ensures a
                // Certificate identity gets the certificate policy id, not the username one.
                if (security.UserIdentity.Type != UserTokenType.Anonymous && selected.UserIdentityTokens != null)
                {
                    var tokenPolicy = selected.UserIdentityTokens
                        .FirstOrDefault(t => t.TokenType == security.UserIdentity.Type);
                    userTokenPolicyId = tokenPolicy?.PolicyId;
                }
            }

            var policy = SecurityPolicyFactory.Create(security.Policy, localCert, remoteCert, resolvedMode);
            _client.SetSecurityPolicy(policy);

            // Use discovered endpoint URL if available, otherwise user-provided
            var effectiveUrl = selected?.EndpointUrl ?? endpointUrl;

            await _client.ConnectAsync(host, port).ConfigureAwait(false);
            await _client.SendHelloAsync(effectiveUrl, _options.MaxMessageSize).ConfigureAwait(false);

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

            var createResponse = await _client.CreateSessionAsync(effectiveUrl, _options.ApplicationName,
                _options.ApplicationUri, _options.ProductUri, (uint)_options.SessionTimeout).ConfigureAwait(false);

            SecurityDebugLogger.LogStage("Connect.CreateSession",
                ("sessionId", createResponse.SessionId),
                ("serverNonceLen", createResponse.ServerNonce?.Length ?? -1),
                ("serverCertLen", createResponse.ServerCertificate?.Length ?? -1),
                ("serverSignatureAlg", createResponse.ServerSignature?.Algorithm),
                ("endpointsCount", createResponse.ServerEndpoints?.Length ?? 0));

            var identity = BuildUserIdentity(security.UserIdentity, createResponse, policy, userTokenPolicyId);
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

        private static string? GetUriFromCertificate(X509Certificate2 cert)
        {
            try
            {
                // SAN OID = 2.5.29.17
                var sanExt = cert.Extensions["2.5.29.17"];
                if (sanExt == null) return null;
                var s = sanExt.Format(false);
                // Format is "URL=uri, DNS Name=host"
                foreach (var part in s.Split(','))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                        return trimmed.Substring(4);
                }
            }
            catch { }
            return null;
        }

        private X509Certificate2? LoadOrGenerateCertificate(CertificateOptions certOptions)
        {
            // Try loading from file first
            if (!string.IsNullOrEmpty(certOptions.CertificatePath) && File.Exists(certOptions.CertificatePath))
            {
                X509Certificate2 cert;
                if (!string.IsNullOrEmpty(certOptions.PrivateKeyPath))
                {
                    (cert, _) = CertificateLoader.LoadCertificateWithKey(
                        certOptions.CertificatePath!, certOptions.PrivateKeyPath!);
                }
                else
                {
                    cert = CertificateLoader.LoadCertificate(certOptions.CertificatePath!, certOptions.PrivateKeyPassword);
                }

                // Sync ApplicationUri to match the loaded certificate's URI SAN
                var certUri = GetUriFromCertificate(cert);
                if (certUri != null && _options.ApplicationUri != certUri)
                {
                    _logger.LogDebug($"Syncing ApplicationUri to cert URI: {certUri}");
                    _options.ApplicationUri = certUri;
                }

                return cert;
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

                // Save to file if path is specified
                if (!string.IsNullOrEmpty(certOptions.CertificatePath))
                {
                    var pfxPassword = certOptions.PrivateKeyPassword ?? "";
                    var pfxBytes = string.IsNullOrEmpty(pfxPassword)
                        ? cert.Export(X509ContentType.Pfx)
                        : cert.Export(X509ContentType.Pfx, pfxPassword);
                    File.WriteAllBytes(certOptions.CertificatePath, pfxBytes);

                    // Also save DER format for servers that don't accept PFX
                    var derPath = Path.ChangeExtension(certOptions.CertificatePath, ".der");
                    File.WriteAllBytes(derPath, cert.RawData);
                }

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
            string? userTokenPolicyId)
        {
            if (identityOptions.Type == UserTokenType.UserName)
            {
                return UserIdentityToken.CreateUserName(
                    identityOptions.Username ?? "",
                    identityOptions.Password ?? "",
                    userTokenPolicyId,
                    createResponse.ServerNonce,
                    createResponse.ServerCertificate,
                    policy.Uri);
            }

            if (identityOptions.Type == UserTokenType.Certificate)
            {
                return new UserIdentityToken
                {
                    TokenType = UserTokenType.Certificate,
                    PolicyId = userTokenPolicyId,
                    IssuedId = policy.SenderCertificate,
                    SecurityPolicyUri = policy.Uri
                };
            }

            return UserIdentityToken.Anonymous();
        }

        /// <summary>Stop the connection and release the session. Returns immediately if already disconnected.</summary>
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
                await sub.AddMonitoredItemAsync(item.NodeId, item.SamplingInterval, item.Handler, item.QueueSize, item.HandlerEx).ConfigureAwait(false);
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

        /// <summary>
        /// Read a single node value. Returns a <see cref="ReadResult"/> with the NodeId and <see cref="DataValue"/>.
        /// Includes automatic reconnect and connection-error retry.
        /// </summary>
        /// <param name="nodeId">The node to read.</param>
        /// <param name="attributeId">The attribute to read, default <see cref="AttributeId.Value"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The <see cref="ReadResult"/>, or <c>null</c> on connection failure or in <see cref="ErrorMode.ReturnNull"/> mode.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="nodeId"/> is <c>null</c>.</exception>
        /// <exception cref="UaConnectionException">Reconnect timed out or failed (<see cref="ErrorMode.Throw"/> mode only).</exception>
        /// <exception cref="UaOperationException">Non-connection error (<see cref="ErrorMode.Throw"/> mode only).</exception>
        public async Task<ReadResult?> ReadAsync(NodeId nodeId, AttributeId attributeId = AttributeId.Value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeId, attributeId), cancellationToken).ConfigureAwait(false);
            if (results == null || results.Length == 0) return null;
            var dv = results[0];
            return new ReadResult { NodeId = nodeId, StatusCode = dv?.StatusCode ?? StatusCode.Bad, DataValue = dv };
        }

        /// <summary>
        /// Read multiple node values in batch. Includes automatic reconnect and connection-error retry.
        /// Each <see cref="ReadResult"/> pairs the input NodeId with its returned <see cref="DataValue"/>.
        /// </summary>
        /// <param name="nodeIds">The nodes to read. Must not be empty.</param>
        /// <param name="attributeId">The attribute to read, default <see cref="AttributeId.Value"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Array of <see cref="ReadResult"/>, one per input node.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="nodeIds"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="nodeIds"/> is an empty array.</exception>
        public async Task<ReadResult[]?> ReadAsync(NodeId[] nodeIds, AttributeId attributeId = AttributeId.Value, CancellationToken cancellationToken = default)
        {
            if (nodeIds == null) throw new ArgumentNullException(nameof(nodeIds));
            if (nodeIds.Length == 0) throw new ArgumentException("NodeIds array cannot be empty", nameof(nodeIds));
            return await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeIds, attributeId), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read a single node and cast to the specified type. Recommended for everyday use.
        /// </summary>
        /// <typeparam name="T">Target type, e.g. <c>int</c>, <c>double</c>, <c>string</c>, <c>DateTime</c>.</typeparam>
        /// <param name="nodeId">The node to read.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The typed value, or <c>default(T)</c> on failure or type mismatch.</returns>
        public async Task<T?> ReadValueAsync<T>(NodeId nodeId, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var result = await ReadAsync(nodeId, AttributeId.Value, cancellationToken).ConfigureAwait(false);
            return ExtractValue<T>(result?.DataValue);
        }

        /// <summary>
        /// Read a specific attribute of a single node and cast to the specified type.
        /// </summary>
        /// <typeparam name="T">Target type.</typeparam>
        /// <param name="nodeId">The node to read.</param>
        /// <param name="attributeId">The attribute to read.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<T?> ReadValueAsync<T>(NodeId nodeId, AttributeId attributeId, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var result = await ReadAsync(nodeId, attributeId, cancellationToken).ConfigureAwait(false);
            return ExtractValue<T>(result?.DataValue);
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

        /// <summary>
        /// Read a node by string NodeId and cast to the specified type. The most convenient read method.
        /// Supports formats like <c>"i=2258"</c>, <c>"ns=2;s=Temperature"</c>.
        /// </summary>
        /// <typeparam name="T">Target type.</typeparam>
        /// <param name="nodeIdString">The NodeId string.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The typed value.</returns>
        public async Task<T?> ReadValueAsync<T>(string nodeIdString, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            var nodeId = ParseNodeId(nodeIdString);
            return await ReadValueAsync<T>(nodeId, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Write a value to a single node. Returns a <see cref="WriteResult"/> with the NodeId and <see cref="StatusCode"/>.
        /// Includes automatic reconnect and connection-error retry. The OPC UA type is inferred from the CLR type automatically.
        /// </summary>
        /// <param name="nodeId">The target node.</param>
        /// <param name="value">The value to write (<c>int</c>, <c>double</c>, <c>string</c>, <c>bool</c>, etc.).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The <see cref="WriteResult"/>, or <c>null</c> on connection failure or in <see cref="ErrorMode.ReturnNull"/> mode.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="nodeId"/> is <c>null</c>.</exception>
        public async Task<WriteResult?> WriteAsync(NodeId nodeId, object value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            var results = await WriteAsync(new[] { new WriteValue { NodeId = nodeId, Value = new DataValue(new Variant(value)) } }, cancellationToken).ConfigureAwait(false);
            return results != null && results.Length > 0 ? results[0] : null;
        }

        /// <summary>
        /// Write multiple nodes in batch (supports different values and types per node).
        /// Each <see cref="WriteResult"/> pairs the input NodeId with its returned <see cref="StatusCode"/>.
        /// </summary>
        /// <param name="values">The nodes and values to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Array of <see cref="WriteResult"/>, one per input.</returns>
        public async Task<WriteResult[]?> WriteAsync(WriteValue[] values, CancellationToken cancellationToken = default)
        {
            if (values == null) throw new ArgumentNullException(nameof(values));
            if (values.Length == 0) throw new ArgumentException("WriteValues array cannot be empty", nameof(values));
            return await ExecuteWithRetryAsync("Write", () => _client!.WriteAsync(values), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Write a value using a string NodeId. The most convenient write method.
        /// </summary>
        /// <param name="nodeIdString">The NodeId string, e.g. <c>"ns=2;s=SetPoint"</c>.</param>
        /// <param name="value">The value to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The <see cref="WriteResult"/> with NodeId and <see cref="StatusCode"/>.</returns>
        public Task<WriteResult?> WriteAsync(string nodeIdString, object value, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            return WriteAsync(ParseNodeId(nodeIdString), value, cancellationToken);
        }

        /// <summary>
        /// Write a strongly-typed value without returning a status code. Use when the result is not needed.
        /// </summary>
        /// <typeparam name="T">The value type.</typeparam>
        /// <param name="nodeId">The target node.</param>
        /// <param name="value">The value to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task WriteValueAsync<T>(NodeId nodeId, T value, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            await WriteAsync(nodeId, value!, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Write a strongly-typed value using a string NodeId.
        /// </summary>
        /// <typeparam name="T">The value type.</typeparam>
        /// <param name="nodeIdString">The NodeId string.</param>
        /// <param name="value">The value to write.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task WriteValueAsync<T>(string nodeIdString, T value, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(nodeIdString))
                throw new ArgumentException("NodeId string cannot be null or empty", nameof(nodeIdString));
            var nodeId = ParseNodeId(nodeIdString);
            await WriteAsync(nodeId, value!, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Browse the children of a node. Each <see cref="BrowseResult"/> contains a
        /// <see cref="BrowseResult.References"/> array of <see cref="ReferenceDescription"/> entries.
        /// If the number of references exceeds <paramref name="maxReferences"/>, the result includes a
        /// <see cref="BrowseResult.ContinuationPoint"/> for use with <see cref="BrowseNextAsync"/>.
        /// </summary>
        /// <param name="nodeId">The starting node.</param>
        /// <param name="direction">Browse direction, default Forward.</param>
        /// <param name="maxReferences">Max references per response, default 100.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Array of browse results.</returns>
        public async Task<BrowseResult[]?> BrowseAsync(NodeId nodeId, BrowseDirection direction = BrowseDirection.Forward, uint maxReferences = 100, CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            return await ExecuteWithRetryAsync("Browse", () => _client!.BrowseAsync(nodeId, direction, maxReferences), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Continue browsing from a previous result. Pass the <see cref="BrowseResult.ContinuationPoint"/>.
        /// </summary>
        /// <param name="continuationPoint">The continuation point from a previous browse.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Subsequent browse results.</returns>
        public async Task<BrowseResult[]?> BrowseNextAsync(byte[] continuationPoint, CancellationToken cancellationToken = default)
        {
            if (continuationPoint == null) throw new ArgumentNullException(nameof(continuationPoint));
            return await ExecuteWithRetryAsync("BrowseNext", () => _client!.BrowseNextAsync(continuationPoint), cancellationToken).ConfigureAwait(false);
        }

        private async Task<Subscription> GetOrCreateDefaultSubscriptionAsync(double interval, CancellationToken cancellationToken = default)
        {
            TaskCompletionSource<Subscription>? pending;
            bool iAmCreator;

            // Dedup and pending-create tracking must use the same resolution, otherwise two
            // near-equal intervals (e.g. 500.0 vs 500.0004) pass the reuse scan yet get distinct
            // raw-double dictionary keys and create duplicate subscriptions. Quantize the key to
            // the same 0.001 ms granularity used by the reuse comparison below.
            double intervalKey = Math.Round(interval, 3);

            lock (_subsLock)
            {

                foreach (var sub in _activeSubscriptions)
                {
                    if (Math.Abs(sub.PublishingInterval - interval) < 0.001)
                        return sub;
                }

                if (_pendingSubscriptionCreates.TryGetValue(intervalKey, out pending))
                {
                    iAmCreator = false;
                }
                else
                {
                    iAmCreator = true;
                    pending = new TaskCompletionSource<Subscription>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingSubscriptionCreates[intervalKey] = pending;
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
                    _pendingSubscriptionCreates.Remove(intervalKey);
            }
        }

        /// <summary>
        /// Create a subscription. Multiple calls with the same <paramref name="publishingInterval"/>
        /// will share a single subscription. Subscriptions are automatically recovered on reconnect.
        /// </summary>
        /// <param name="publishingInterval">Publishing interval in milliseconds, default 1000.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A <see cref="Subscription"/> with publishing already started.</returns>
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

        /// <summary>Delete a subscription and all its monitored items.</summary>
        /// <param name="subscription">The subscription to delete.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DeleteSubscriptionAsync(Subscription subscription, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            _reconnectEngine?.UnregisterSubscription(subscription.SubscriptionId);
            lock (_subsLock)
                _activeSubscriptions.Remove(subscription);
            await subscription.DeleteAsync().ConfigureAwait(false);
        }

        /// <summary>Delete specific monitored items from a subscription.</summary>
        /// <param name="subscription">The parent subscription.</param>
        /// <param name="monitoredItemIds">The monitored item IDs to remove.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Status code for each delete operation.</returns>
        public async Task<StatusCode[]> DeleteMonitoredItemsAsync(Subscription subscription, uint[] monitoredItemIds, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            return await subscription.DeleteMonitoredItemsAsync(monitoredItemIds).ConfigureAwait(false);
        }

        /// <summary>
        /// Subscribe to data changes for a single node. Creates or reuses a subscription at the same interval.
        /// The returned <c>MonitoredItemId</c> can be used with <see cref="DeleteMonitoredItemsAsync"/>.
        /// </summary>
        /// <param name="nodeId">The node to monitor.</param>
        /// <param name="handler">Data change callback <see cref="DataChangeHandler"/>.</param>
        /// <param name="interval">Sampling interval in milliseconds, default 1000.</param>
        /// <param name="queueSize">Queue size, 0 for default.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Subscription and monitored item ID tuple.</returns>
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

        /// <summary>
        /// Subscribe to multiple nodes in batch. All nodes share the same callback and sampling interval.
        /// </summary>
        /// <param name="nodeIds">The nodes to monitor.</param>
        /// <param name="handler">Data change callback.</param>
        /// <param name="interval">Sampling interval in milliseconds.</param>
        /// <param name="queueSize">Queue size.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The subscription.</returns>
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

        /// <summary>
        /// Subscribe to data changes for a single node with an extended callback that also
        /// receives the source and server timestamps. Same (nodeId, value, status) as the
        /// standard callback plus <c>sourceTimestamp</c>/<c>serverTimestamp</c> (nullable).
        /// </summary>
        /// <param name="nodeId">The node to monitor.</param>
        /// <param name="handler">Extended data change callback <see cref="DataChangeHandlerEx"/>.</param>
        /// <param name="interval">Sampling interval in milliseconds, default 1000.</param>
        /// <param name="queueSize">Queue size, 0 for default.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Subscription and monitored item ID tuple.</returns>
        public async Task<(Subscription Subscription, uint MonitoredItemId)> SubscribeAsync(
            NodeId nodeId, DataChangeHandlerEx handler, double interval = 1000.0, uint queueSize = 0,
            CancellationToken cancellationToken = default)
        {
            if (nodeId == null) throw new ArgumentNullException(nameof(nodeId));
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            var item = await sub.AddMonitoredItemAsync(nodeId, interval, handler: null, queueSize, handlerEx: handler).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, queueSize, handler: null, handlerEx: handler);
            return (sub, item.MonitoredItemId);
        }

        /// <summary>
        /// Subscribe to multiple nodes in batch with an extended callback that also receives
        /// the source and server timestamps. All nodes share the same callback and interval.
        /// </summary>
        /// <param name="nodeIds">The nodes to monitor.</param>
        /// <param name="handler">Extended data change callback <see cref="DataChangeHandlerEx"/>.</param>
        /// <param name="interval">Sampling interval in milliseconds.</param>
        /// <param name="queueSize">Queue size.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The subscription.</returns>
        public async Task<Subscription> SubscribeAsync(NodeId[] nodeIds, DataChangeHandlerEx handler, double interval = 1000.0, uint queueSize = 0, CancellationToken cancellationToken = default)
        {
            if (nodeIds == null) throw new ArgumentNullException(nameof(nodeIds));
            if (nodeIds.Length == 0) throw new ArgumentException("NodeIds array cannot be empty", nameof(nodeIds));
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < nodeIds.Length; i++)
            {
                await sub.AddMonitoredItemAsync(nodeIds[i], interval, handler: null, queueSize, handlerEx: handler).ConfigureAwait(false);
                UpdateTemplate(sub, nodeIds[i], interval, queueSize, handler: null, handlerEx: handler);
            }
            return sub;
        }

        private void UpdateTemplate(Subscription sub, NodeId nodeId, double samplingInterval, uint queueSize, DataChangeHandler? handler, DataChangeHandlerEx? handlerEx = null)
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
                        Handler = handler,
                        HandlerEx = handlerEx
                    }
                }
            }, sub);
        }

        /// <summary>
        /// Parse an OPC UA NodeId string. Supported formats:
        /// <c>"i=2258"</c> (numeric), <c>"s=Temperature"</c> (string),
        /// <c>"g=..."</c> (GUID), <c>"ns=2;s=Temperature"</c> (with namespace).
        /// </summary>
        /// <param name="nodeIdString">The NodeId string to parse.</param>
        /// <exception cref="ArgumentException"><paramref name="nodeIdString"/> is null, empty, or unrecognized.</exception>
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

        /// <summary>
        /// Release client resources: disconnect, stop reconnect engine, release socket.
        /// Safe to call multiple times (idempotent).
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

            try { await StopAsyncCore().ConfigureAwait(false); } catch { }
            try { _reconnectEngine?.Dispose(); } catch { }
            try { _client?.Dispose(); } catch { }
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Subscribe to data changes with a type-safe callback. OPC UA values are automatically cast to <typeparamref name="T"/>.
        /// This is the most commonly used subscription method.
        /// </summary>
        /// <typeparam name="T">The data type.</typeparam>
        /// <param name="nodeIdString">The NodeId string.</param>
        /// <param name="onDataChanged">Type-safe callback <c>Action&lt;T?&gt;</c>.</param>
        /// <param name="interval">Sampling interval in milliseconds, default 1000.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The subscription—call <c>Dispose()</c> to unsubscribe.</returns>
        /// <example>
        /// <code>
        /// var sub = await client.SubscribeAsync&lt;DateTime&gt;("i=2258", val =>
        ///     Console.WriteLine($"Tick: {val:HH:mm:ss.fff}"), interval: 500);
        /// </code>
        /// </example>
        public async Task<Subscription> SubscribeAsync<T>(
            string nodeIdString,
            Action<T?> onDataChanged,
            double interval = 1000.0,
            CancellationToken cancellationToken = default)
        {
            var nodeId = NodeId.Parse(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (_, value, status) =>
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

        /// <summary>
        /// Subscribe to data changes with a type-safe callback that includes the quality <see cref="StatusCode"/>.
        /// Useful when you need to know both the value and its quality.
        /// </summary>
        /// <typeparam name="T">The data type.</typeparam>
        /// <param name="nodeIdString">The NodeId string.</param>
        /// <param name="onDataChanged">Callback <c>Action&lt;T?, StatusCode&gt;</c> — second argument is the quality.</param>
        /// <param name="interval">Sampling interval in milliseconds, default 1000.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The subscription.</returns>
        public async Task<Subscription> SubscribeAsync<T>(
            string nodeIdString,
            Action<T?, StatusCode> onDataChanged,
            double interval = 1000.0,
            CancellationToken cancellationToken = default)
        {
            var nodeId = NodeId.Parse(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (_, value, status) =>
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

        /// <summary>
        /// Start the fluent configuration chain. Use <c>.WithSecurity(...)</c>, <c>.WithUserName(...)</c>,
        /// <c>.WithAppName(...)</c>, etc., then call <c>.BuildAndRunAsync()</c> to connect.
        /// </summary>
        /// <param name="endpointUrl">OPC UA server URL, e.g. <c>opc.tcp://localhost:4840</c>.</param>
        /// <returns>A <see cref="ClientBuilder"/> for fluent configuration.</returns>
        public static ClientBuilder ConnectTo(string endpointUrl)
            => new ClientBuilder(endpointUrl);

        /// <summary>
        /// Start the fluent configuration chain from a <see cref="Uri"/>.
        /// </summary>
        public static ClientBuilder ConnectTo(Uri endpointUri)
            => new ClientBuilder(endpointUri.ToString());

        /// <summary>
        /// Fluent builder for configuring and connecting a <see cref="UaClient"/>.
        /// All <c>With*</c> methods return the builder for chaining.
        /// Call <see cref="Build"/> to create the client without connecting,
        /// or <see cref="BuildAndRunAsync"/> to create and connect immediately.
        /// </summary>
        public class ClientBuilder
        {
            private readonly string _endpointUrl;

            private readonly UaClientOptions _options = UaClientOptions.Default;
            private bool _reconnect = true;
            private ILogger? _logger;

            internal ClientBuilder(string endpointUrl) { _endpointUrl = endpointUrl; }

            /// <summary>Set per-step network timeout (socket I/O and reconnect attempts). Default 30000ms.</summary>
            /// <param name="milliseconds">Timeout in milliseconds.</param>
            public ClientBuilder WithRequestTimeout(int milliseconds) { _options.Timeout = (uint)milliseconds; return this; }

            /// <summary>Set the application name displayed in server session diagnostics. Also updates the ApplicationUri.</summary>
            public ClientBuilder WithAppName(string name) { _options.ApplicationName = name; _options.ApplicationUri = $"urn:{name}:{Guid.NewGuid()}"; return this; }

            /// <summary>Disable automatic reconnect. Equivalent to <c>WithReconnectRetries(0)</c>.</summary>
            public ClientBuilder WithoutReconnect() { _reconnect = false; return this; }

            /// <summary>Set maximum reconnect attempts. Default -1 (infinite). Set to 0 to disable.</summary>
            public ClientBuilder WithReconnectRetries(int maxRetries) { _options.ReconnectMaxRetries = maxRetries; return this; }

            /// <summary>Set the session timeout in milliseconds. Default 3600000 (1 hour).</summary>
            public ClientBuilder WithSessionTimeout(int ms) { _options.SessionTimeout = ms; return this; }

            /// <summary>Set the error handling strategy. Default <see cref="ErrorMode.Throw"/>.</summary>
            public ClientBuilder WithErrorMode(ErrorMode mode) { _options.ErrorMode = mode; return this; }

            /// <summary>
            /// Set the security policy by short name (e.g. <c>"Basic256Sha256"</c>, <c>"Aes128_Sha256_RsaOaep"</c>,
            /// <c>"Aes256_Sha256_RsaPss"</c>, <c>"None"</c>). Non-None policies auto-enable SignAndEncrypt mode.
            /// </summary>
            public ClientBuilder WithSecurity(string policy)
            {
                _options.Security.Policy = policy;
                if (policy != "None")
                    _options.Security.Mode = TinyUa.Core.Security.MessageSecurityMode.SignAndEncrypt;
                return this;
            }

            /// <summary>Configure security with a callback for full control over <see cref="SecurityOptions"/>.</summary>
            /// <param name="configure">Action that receives the <see cref="SecurityOptions"/> to modify.</param>
            public ClientBuilder WithSecurity(Action<SecurityOptions> configure)
            {
                configure(_options.Security);
                return this;
            }

            /// <summary>Set username/password authentication. The password is RSA-OAEP encrypted before transmission.</summary>
            /// <param name="username">The username.</param>
            /// <param name="password">The password (plaintext, will be encrypted for transmission).</param>
            public ClientBuilder WithUserName(string username, string password)
            {
                _options.Security.UserIdentity.Type = TinyUa.Core.Security.UserTokenType.UserName;
                _options.Security.UserIdentity.Username = username;
                _options.Security.UserIdentity.Password = password;
                return this;
            }

            /// <summary>Attach a custom <see cref="ILogger"/> implementation.</summary>
            public ClientBuilder WithLogger(ILogger logger) { _logger = logger; return this; }

            /// <summary>Enable console logging via a simple callback. For custom loggers, use <see cref="WithLogger"/> instead.</summary>
            /// <param name="sink">Callback receiving (LogLevel, Exception?, message).</param>
            /// <param name="minLevel">Minimum log level to record. Default <see cref="LogLevel.Debug"/>.</param>
            public ClientBuilder EnableLog(Action<LogLevel, Exception?, string> sink, LogLevel minLevel = LogLevel.Debug)
            {
                _logger = new DelegateLogger(sink, minLevel);
                return this;
            }

            /// <summary>Enable logging to a directory. Log files are auto-created and auto-rotated.</summary>
            /// <param name="directory">Directory path for log files (created if needed).</param>
            /// <param name="minLevel">Minimum log level. Default <see cref="LogLevel.Debug"/>.</param>
            /// <param name="async">Use asynchronous file writes. Default false.</param>
            public ClientBuilder EnableLogFile(string directory, LogLevel minLevel = LogLevel.Debug, bool async = false)
            {
                _logger = new FileLogger(directory, minLevel, async);
                return this;
            }

            /// <summary>Build the <see cref="UaClient"/> without connecting. Call <see cref="UaClient.RunAsync()"/> to connect later.</summary>
            public UaClient Build()
            {
                _options.ReconnectMaxRetries = _reconnect ? _options.ReconnectMaxRetries : 0;
                var client = new UaClient(_options, _logger);
                client._endpointUrl = _endpointUrl;
                return client;
            }

            /// <summary>Build the client and connect immediately. Equivalent to <c>Build()</c> followed by <c>RunAsync()</c>.</summary>
            /// <returns>A connected <see cref="UaClient"/> ready for operations.</returns>
            public async Task<UaClient> BuildAndRunAsync()
            {
                var client = Build();
                await client.RunAsync().ConfigureAwait(false);
                return client;
            }
        }
    }
}
