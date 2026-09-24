using TinyUa.Core;
using System;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;
using TinyUa.Client.Services;
using TinyUa.Client.Connection;
using TinyUa.Client.Subscriptions;

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
    /// <remarks>
    /// This type is a facade: the connect handshake lives in <c>ConnectionOrchestrator</c>,
    /// lifecycle state in <c>ClientStateMachine</c>, subscription bookkeeping in
    /// <c>SubscriptionRegistry</c>, and reconnect logic in <c>ReconnectEngine</c>.
    /// </remarks>
    public partial class UaClient : IAsyncDisposable
    {
        private readonly UaConnection _client;
        private readonly SubscriptionRouter _subscriptionRouter;
        private readonly ConnectionOrchestrator _orchestrator;
        private readonly ClientStateMachine _stateMachine = new();
        private readonly SubscriptionRegistry _subscriptions = new();
        private readonly UaClientOptions _options;
        private readonly ILogger _logger;
        private IDisposable? _ownedLogger;
        private volatile string? _endpointUrl;
        private int _disposed;
        private volatile KeepAliveManager? _keepAliveManager;
        private volatile ReconnectEngine? _reconnectEngine;

        private Task? _stopTask;
        private Task? _disposeTask;
        private readonly object _lifecycleLock = new();
        private Task? _runTask;
        private CancellationTokenSource? _runCancellation;
        private volatile bool _stopRequested;

        private readonly record struct ReconnectRequest(
            ReconnectEngine? Engine,
            string? EndpointUrl,
            bool CanReconnect,
            bool StateChanged)
        {
            internal bool IsReady => CanReconnect && Engine != null && !string.IsNullOrEmpty(EndpointUrl);
        }

        /// <summary>Whether the client is currently connected and the underlying channel is alive.</summary>
        public bool IsConnected => _stateMachine.State == ClientState.Connected && _client.IsAlive;

        /// <summary>The session ID assigned by the server after a successful connection.</summary>
        public NodeId? SessionId => _client?.SessionId;

        /// <summary>
        /// The private options snapshot taken at construction time. Mutations of the object passed
        /// to the constructor have no effect on a running client.
        /// </summary>
        public UaClientOptions Options => _options.Clone();

        /// <summary>The actual channel lifetime negotiated with the server (milliseconds).</summary>
        public uint RevisedChannelLifetime => _client?.RevisedChannelLifetime ?? 0;

        /// <summary>Current client connection state.</summary>
        public ClientState State => _stateMachine.State;

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
        /// <param name="options">Client configuration. Must not be <c>null</c>. A deep copy is taken.</param>
        /// <param name="logger">Optional logger.</param>
        public UaClient(UaClientOptions options, ILogger? logger = null)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            _options = options.Clone();
            _logger = logger ?? NullLogger.Instance;
            _client = new UaConnection((int)_options.Timeout, _logger);
            _subscriptionRouter = new SubscriptionRouter(_client, _logger);
            _orchestrator = new ConnectionOrchestrator(_client, _options, _logger);
            _stateMachine.StateChanged += RaiseStateChanged;
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
        /// <exception cref="OperationCanceledException">The connection attempt was cancelled.</exception>
        public Task RunAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            lock (_lifecycleLock)
            {
                if (_stopRequested) throw new InvalidOperationException("Stop is still in progress.");
                if (_runTask is { IsCompleted: false }) return _runTask.WaitAsync(cancellationToken);
                if (IsConnected) return Task.CompletedTask;
                if (_stateMachine.State == ClientState.Reconnecting) return EnsureConnectedAsync(cancellationToken);
                _runCancellation?.Dispose();
                _runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var token = _runCancellation.Token;
                _runTask = Task.Run(() => RunCoreAsync(token), CancellationToken.None);
                return AwaitOwnedRunAsync(_runTask, cancellationToken);
            }
        }

        private static async Task AwaitOwnedRunAsync(Task run, CancellationToken callerToken)
        {
            try { await run.ConfigureAwait(false); }
            catch (OperationCanceledException ex) when (callerToken.IsCancellationRequested)
            { throw new OperationCanceledException("Connection attempt cancelled.", ex, callerToken); }
        }

        private async Task RunCoreAsync(CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(_endpointUrl))
                throw new InvalidOperationException(
                    "No endpoint URL. Use new OpcUaClient(url) or OpcUaClient.ConnectTo(url).Build().");

            ThrowIfDisposed();

            cancellationToken.ThrowIfCancellationRequested();
            bool startConnecting = _stateMachine.Transition(state =>
            {
                ThrowIfDisposed();
                if (state == ClientState.Connected || state == ClientState.Connecting) return null;
                if (state == ClientState.Disconnecting) return null;
                return ClientState.Connecting;
            });
            if (!startConnecting) return;

            var retries = 0;
            var backoff = new BackoffPolicy(_options.ReconnectInitialDelayMs, _options.ReconnectMaxDelayMs, jitter: true);
            var maxRetries = _options.ReconnectMaxRetries;

            while (maxRetries < 0 || retries <= maxRetries)
            {
                try
                {
                    await ConnectInternalAsync(_endpointUrl, cancellationToken).ConfigureAwait(false);

                    return;
                }
                catch (Exception ex) when (cancellationToken.IsCancellationRequested)
                {
                    await AbortConnectAsync().ConfigureAwait(false);
                    throw new OperationCanceledException("Connection attempt cancelled.", ex, cancellationToken);
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    await AbortConnectAsync().ConfigureAwait(false);

                    retries++;
                    if (maxRetries >= 0 && retries > maxRetries)
                    {
                        if (_options.ErrorMode == ErrorMode.Throw)
                            throw new UaConnectionException(
                                $"Failed to connect to {_endpointUrl} after {retries} attempts", ex);
                        return;
                    }

                    bool reentered = _stateMachine.Transition(state =>
                    {
                        if (IsDisposed || cancellationToken.IsCancellationRequested || state == ClientState.Disconnecting) return null;
                        return ClientState.Connecting;
                    });
                    if (!reentered) return;

                    var delay = backoff.NextDelay();
                    _logger.LogWarning(ex, $"Connect attempt {retries} failed, retrying in {delay}ms");
                    try { await Task.Delay(delay, cancellationToken).ConfigureAwait(false); }
                    catch (OperationCanceledException)
                    {
                        await AbortConnectAsync().ConfigureAwait(false);
                        throw;
                    }
                }
            }
        }

        private async Task AbortConnectAsync()
        {
            // A failed/cancelled handshake may already have a session but an unresponsive
            // peer. Close the transport first so graceful cleanup cannot wait on that peer.
            StopAndDisposeKeepAlive();
            try { await _client.DisconnectAsync().ConfigureAwait(false); } catch { }
            try { await _client.CloseSessionAsync().ConfigureAwait(false); } catch { }
            _client.ConnectionLost -= OnSocketConnectionLost;
            _stateMachine.Transition(state => state == ClientState.Disconnecting ? null : ClientState.Disconnected);
        }

        private async Task ConnectInternalAsync(string endpointUrl, CancellationToken cancellationToken)
        {
            _endpointUrl = endpointUrl;

            using var loggerScope = SecurityDebugLogger.BeginScope(_logger);

            await _orchestrator.ConnectAsync(endpointUrl, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            _client.ConnectionLost -= OnSocketConnectionLost;
            _client.ConnectionLost += OnSocketConnectionLost;

            // Warmup read: Server.ServerStatus.State (i=2259) — the same node KeepAliveManager
            // polls later. Reading it once here pre-compiles (JIT) the entire Read call stack
            // (ExecuteWithRetryAsync<ReadResult[]> → UaConnection.ReadAsync(NodeId[]) →
            // ReadRequest.Encode / ReadResponse.Decode / DataValue / Variant decoding) so the
            // caller's first business Read doesn't pay the one-time ~4ms JIT cost. A failure here
            // only logs a warning: the connection itself has already succeeded.
            if (_options.WarmupOnConnect)
            {
                try
                {
                    // Read both a scalar (ServerStatus.State, i=2259 — UInt32) and an array
                    // (ServerArray, i=2254 — String[]) so that VariantCodec.DecodeScalarValue AND
                    // VariantCodec.DecodeArrayValue are JIT-compiled before the caller's first
                    // business Read. Without the array node, the first Read returning an array
                    // (e.g. ServerArray, NodeIds[]) pays a one-time ~0.3ms JIT cost for
                    // DecodeArrayValue — the last remaining gap vs. the OPCF SDK's first-read
                    // latency.
                    var warmupResults = await _client.ReadAsync(
                        new[] { new NodeId(2259u), new NodeId(2254u) }, AttributeId.Value, cancellationToken).ConfigureAwait(false);
                    if (warmupResults is { Length: > 0 } && warmupResults[0].StatusCode.IsGood)
                    {
                        _logger.LogDebug($"Warmup read OK: ServerStatus.State={warmupResults[0].DataValue?.Value?.Value}, ServerArray=[{warmupResults.Length}] nodes");
                    }
                    else
                    {
                        _logger.LogWarning("Warmup read returned a bad or empty result (ignored)");
                    }
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning(ex, "Warmup read of Server.ServerStatus failed (ignored)");
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            var sessionId = _client.SessionId;
            var authToken = _client.AuthenticationToken ?? new NodeId();
            _reconnectEngine?.Dispose();
            var engine = new ReconnectEngine(_client, _options, _logger);
            _reconnectEngine = engine;
            _reconnectEngine.ReconnectCompleted += (lossless) =>
            {
                if (!_stateMachine.Transition(state => !IsDisposed && !_stopRequested
                    && ReferenceEquals(_reconnectEngine, engine) && state == ClientState.Reconnecting
                    ? ClientState.Connected : null)) return;

                StartKeepAlive();

                // Publishing was stopped when the connection dropped; the session-level publish
                // engine must be re-attached or a losslessly recovered session would receive
                // republished history but no further live notifications.
                foreach (var sub in _subscriptions.Snapshot())
                {
                    try { sub.StartPublishing(); } catch { }
                }

                RaiseSubscriptionsRecovered(lossless);
            };
            _reconnectEngine.ReconnectFailed += () => _stateMachine.Transition(state =>
                ReferenceEquals(_reconnectEngine, engine) && state == ClientState.Reconnecting
                    ? ClientState.Disconnected : null);
            _reconnectEngine.ReconnectBackoff += RaiseReconnectBackoff;

            if (sessionId != null)
                _reconnectEngine.OnSessionEstablished(sessionId, authToken);

            cancellationToken.ThrowIfCancellationRequested();
            bool connectCompleted = _stateMachine.Transition(state =>
                !IsDisposed && !_stopRequested && state == ClientState.Connecting
                    ? ClientState.Connected : null);
            if (connectCompleted && !_stopRequested) StartKeepAlive();
        }

        /// <summary>Stop the connection and release the session. Returns immediately if already disconnected.</summary>
        public Task StopAsync()
        {

            if (IsDisposed) return _disposeTask ?? Task.CompletedTask;
            return StopAsyncCore();
        }

        private Task StopAsyncCore()
        {
            lock (_lifecycleLock)
            {
                if (_stopTask is { IsCompleted: false }) return _stopTask;
                _stopRequested = true;
                _runCancellation?.Cancel();
                var connecting = _runTask;
                _stopTask = Task.Run(() => StopOwnedLifecycleAsync(connecting));
                return _stopTask;
            }
        }

        private async Task StopOwnedLifecycleAsync(Task? connecting)
        {
            if (connecting != null) { try { await connecting.ConfigureAwait(false); } catch { } }
            if (_reconnectEngine != null) await _reconnectEngine.StopAsync().ConfigureAwait(false);
            _client.ConnectionLost -= OnSocketConnectionLost;
            _stateMachine.Set(ClientState.Disconnecting);

            // The transition above already raised StateChanged(Disconnecting).
            try
            {
                _reconnectEngine?.CancelReconnect();
                StopAndDisposeKeepAlive();

                var subsToDispose = _subscriptions.DrainForShutdown(new ObjectDisposedException(nameof(UaClient)));
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
                _stateMachine.Set(ClientState.Disconnected);

                lock (_lifecycleLock) _stopRequested = false;
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
            var channelLifetime = _client.RevisedChannelLifetime > 0
                ? _client.RevisedChannelLifetime
                : _options.ChannelLifetime;
            _keepAliveManager = new KeepAliveManager(_client, (int)Math.Clamp(_client.RevisedSessionTimeout > 0 ? _client.RevisedSessionTimeout : _options.SessionTimeout, 1, int.MaxValue), (int)channelLifetime,
                _logger, _options.SessionKeepAliveIntervalMs);
            _keepAliveManager.Start();
        }

        private void RaiseStateChanged(ClientState state)
        {
            var handlers = StateChanged;
            if (handlers == null) return;
            foreach (Action<ClientState> handler in handlers.GetInvocationList())
            {
                try { handler(state); }
                catch (Exception ex) { _logger.LogWarning(ex, "StateChanged event handler threw"); }
            }
        }

        private void RaiseSubscriptionsRecovered(bool lossless)
        {
            var handlers = SubscriptionsRecovered;
            if (handlers == null) return;
            foreach (Action<bool> handler in handlers.GetInvocationList())
            {
                try { handler(lossless); }
                catch (Exception ex) { _logger.LogWarning(ex, "SubscriptionsRecovered event handler threw"); }
            }
        }

        private void RaiseReconnectBackoff(int retry, int delay)
        {
            var handlers = ReconnectBackoff;
            if (handlers == null) return;
            foreach (Action<int, int> handler in handlers.GetInvocationList())
            {
                try { handler(retry, delay); }
                catch (Exception ex) { _logger.LogWarning(ex, "ReconnectBackoff event handler threw"); }
            }
        }

        private void OnSocketConnectionLost(Exception? ex)
        {

            var actualEx = ex ?? new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionReset);
            OnConnectionLostAsync(actualEx).Forget(_logger, nameof(OnConnectionLostAsync));
        }

        private async Task OnConnectionLostAsync(Exception ex)
        {
            _logger.LogWarning(ex, "Connection lost — triggering reconnect");

            var reconnect = EnterReconnecting();
            if (!reconnect.StateChanged)
                return;

            if (reconnect.IsReady)
                await reconnect.Engine!.ReconnectAsync(reconnect.EndpointUrl!, RebuildSubscriptionAsync);
        }

        /// <summary>
        /// The sole entry point for moving a live client into reconnecting. It captures the
        /// engine under the same state lock as the transition, so concurrent socket failures and
        /// request failures share one reconnect task and emit at most one StateChanged event.
        /// </summary>
        private ReconnectRequest EnterReconnecting()
        {
            ReconnectEngine? engine = null;
            string? endpointUrl = null;
            var canReconnect = false;
            var stateChanged = _stateMachine.Transition(state =>
            {
                if (IsDisposed || _stopRequested || state == ClientState.Connecting || state == ClientState.Disconnecting || state == ClientState.Disconnected)
                    return null;

                engine = _reconnectEngine;
                endpointUrl = _endpointUrl;
                canReconnect = engine != null && !string.IsNullOrEmpty(endpointUrl);
                return state == ClientState.Reconnecting ? null : ClientState.Reconnecting;
            });

            if (stateChanged)
            {
                StopAndDisposeKeepAlive();
                foreach (var sub in _subscriptions.Snapshot())
                {
                    try { sub.StopPublishing(); } catch { }
                }
            }

            return new ReconnectRequest(engine, endpointUrl, canReconnect, stateChanged);
        }

        private void StartBackgroundReconnect()
        {
            var request = EnterReconnecting();
            if (request.StateChanged && request.IsReady)
                request.Engine!.ReconnectAsync(request.EndpointUrl!, RebuildSubscriptionAsync).Forget(_logger, "Background reconnect");
        }

        private async Task<Subscription?> RebuildSubscriptionAsync(SubscriptionTemplate template)
        {
            var subscription = template.ActiveSubscription;
            if (subscription == null || subscription.IsSubscriptionDisposed) return null;
            await subscription.RebuildAsync(template.CancellationToken).ConfigureAwait(false);
            template.SubscriptionId = subscription.SubscriptionId;
            return subscription;
        }

        private async Task EnsureConnectedAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            if (_stateMachine.State == ClientState.Connected && _client.IsAlive)
                return;

            var reconnect = EnterReconnecting();
            if (!reconnect.IsReady)
                throw new UaConnectionException("Client is not connected. Call RunAsync() first.");

            if (reconnect.StateChanged)
                _logger.LogWarning($"EnsureConnectedAsync: connection dead (alive={_client.IsAlive}) — triggering reconnect");

            var success = await reconnect.Engine!.ReconnectAsync(reconnect.EndpointUrl!, RebuildSubscriptionAsync)
                .WithTimeout((int)_options.Timeout, "Timed out waiting for reconnection")
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            if (success)
            {

                return;
            }
            throw new UaConnectionException($"Reconnect failed after max retries ({_options.ReconnectMaxRetries})");
        }

        internal static bool IsConnectionError(Exception ex)
        {
            if (ex is System.Net.Sockets.SocketException) return true;
            if (ex is System.IO.IOException) return true;
            if (ex is UaException ua)
            {

                return (ua.StatusCode & 0xFFFF0000) is 0x80860000 or 0x80220000
                    or 0x80250000 or 0x80260000 or 0x80850000 or 0x808A0000 or 0x80AE0000;
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
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (TimeoutException ex)
                {

                    _logger.LogWarning(ex, $"{operationName} timed out waiting for reconnection");
                    StartBackgroundReconnect();
                    if (_options.ErrorMode == ErrorMode.Throw)
                        throw new UaConnectionException($"{operationName} timed out waiting for reconnection");
                    return null;
                }
                catch (Exception ex) when (attempt == 0 && operationName != "Write" && IsConnectionError(ex))
                {
                    _logger.LogWarning(ex, $"{operationName} failed with connection error — reconnecting and retrying");
                    EnterReconnecting();
                    continue;
                }
                catch (Exception ex)
                {
                    if (IsConnectionError(ex)) StartBackgroundReconnect();
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
            var results = await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeId, attributeId, cancellationToken), cancellationToken).ConfigureAwait(false);
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
            return await ExecuteWithRetryAsync("Read", () => _client!.ReadAsync(nodeIds, attributeId, cancellationToken), cancellationToken).ConfigureAwait(false);
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
        /// Waits for an available connection but never automatically replays an uncertain Write.
        /// The OPC UA type is inferred from the CLR type automatically.
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
            return await ExecuteWithRetryAsync("Write", () => _client!.WriteAsync(values, cancellationToken), cancellationToken).ConfigureAwait(false);
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
            return await ExecuteWithRetryAsync("Browse", () => _client!.BrowseAsync(nodeId, direction, maxReferences, cancellationToken), cancellationToken).ConfigureAwait(false);
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
            return await ExecuteWithRetryAsync("BrowseNext", () => _client!.BrowseNextAsync(continuationPoint, cancellationToken), cancellationToken).ConfigureAwait(false);
        }

        private Task<Subscription> GetOrCreateDefaultSubscriptionAsync(double interval, CancellationToken cancellationToken = default)
            => _subscriptions.GetOrCreateAsync(interval, () => CreateSubscriptionAsync(interval, cancellationToken), cancellationToken);

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

            var sub = await SubscriptionManager.CreateSubscriptionAsync(
                _subscriptionRouter,
                publishingInterval,
                autoStart: true,
                _options.MaxPublishRequests,
                _logger,
                _options.SubscriptionDispatch, cancellationToken).ConfigureAwait(false);

            var template = new SubscriptionTemplate
            {
                SubscriptionId = sub.SubscriptionId,
                PublishingInterval = publishingInterval,
                LifetimeCount = sub.LifetimeCount,
                MaxKeepAliveCount = sub.MaxKeepAliveCount,
                MaxPublishRequests = _options.MaxPublishRequests
            };
            sub.Disposed += OnSubscriptionDisposed;
            lock (_lifecycleLock)
            {
                if (_stopRequested || State != ClientState.Connected || IsDisposed)
                { sub.Dispose(); throw new UaConnectionException("Connection stopped during subscription creation."); }
                _reconnectEngine?.RegisterSubscription(template, sub);
                _subscriptions.Add(sub);
            }
            return sub;
        }

        /// <summary>Delete a subscription and all its monitored items.</summary>
        /// <param name="subscription">The subscription to delete.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task DeleteSubscriptionAsync(Subscription subscription, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            _reconnectEngine?.UnregisterSubscription(subscription);
            _subscriptions.Remove(subscription);
            await subscription.DeleteAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Delete specific monitored items from a subscription.</summary>
        /// <param name="subscription">The parent subscription.</param>
        /// <param name="monitoredItemIds">Stable logical IDs returned by SubscribeAsync, valid across reconnects.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Status code for each delete operation.</returns>
        public async Task<StatusCode[]> DeleteMonitoredItemsAsync(Subscription subscription, uint[] monitoredItemIds, CancellationToken cancellationToken = default)
        {
            if (subscription == null) throw new ArgumentNullException(nameof(subscription));
            return await subscription.DeleteMonitoredItemsAsync(monitoredItemIds, cancellationToken).ConfigureAwait(false);
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
            var item = await sub.AddMonitoredItemAsync(nodeId, handler, queueSize, cancellationToken).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, queueSize, handler, clientHandle: item.ClientHandle);
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
            await sub.AddBatchAsync(nodeIds, interval, handler, queueSize, null, cancellationToken).ConfigureAwait(false);
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
            var item = await sub.AddMonitoredItemAsync(nodeId, interval, handler: null, queueSize, handlerEx: handler, cancellationToken: cancellationToken).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, queueSize, handler: null, handlerEx: handler, clientHandle: item.ClientHandle);
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
            await sub.AddBatchAsync(nodeIds, interval, null, queueSize, handler, cancellationToken).ConfigureAwait(false);
            return sub;
        }

        private void OnSubscriptionDisposed(Subscription sub)
        {
            _reconnectEngine?.UnregisterSubscription(sub);
            _subscriptions.Remove(sub);
            sub.Disposed -= OnSubscriptionDisposed;
        }

        private void UpdateTemplate(Subscription sub, NodeId nodeId, double samplingInterval, uint queueSize, DataChangeHandler? handler, DataChangeHandlerEx? handlerEx = null, uint clientHandle = 0)
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
                        ClientHandle = clientHandle,
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
        public ValueTask DisposeAsync()
        {
            lock (_lifecycleLock)
            {
                if (_disposeTask != null) return new ValueTask(_disposeTask);
                Interlocked.Exchange(ref _disposed, 1);
                _disposeTask = Task.Run(DisposeOwnedClientAsync);
                return new ValueTask(_disposeTask);
            }
        }

        private async Task DisposeOwnedClientAsync()
        {
            try { await StopAsyncCore().ConfigureAwait(false); } catch { }
            try { _reconnectEngine?.Dispose(); } catch { }
            try { await _client.DisposeAsync().ConfigureAwait(false); } catch { }
            _runCancellation?.Dispose();
            _ownedLogger?.Dispose();
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
            var nodeId = ParseNodeId(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (_, value, status) =>
            {
                if (status.IsGood && value is T typed)
                    onDataChanged(typed);
                else
                    onDataChanged(default);
            };
            var item = await sub.AddMonitoredItemAsync(nodeId, handler, cancellationToken: cancellationToken).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, 0, handler, clientHandle: item.ClientHandle);
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
            var nodeId = ParseNodeId(nodeIdString);
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var sub = await GetOrCreateDefaultSubscriptionAsync(interval, cancellationToken).ConfigureAwait(false);
            DataChangeHandler handler = (_, value, status) =>
            {
                if (status.IsGood && value is T typed)
                    onDataChanged(typed, status);
                else
                    onDataChanged(default, status);
            };
            var item = await sub.AddMonitoredItemAsync(nodeId, handler, cancellationToken: cancellationToken).ConfigureAwait(false);
            UpdateTemplate(sub, nodeId, interval, 0, handler, clientHandle: item.ClientHandle);
            return sub;
        }
    }
}
