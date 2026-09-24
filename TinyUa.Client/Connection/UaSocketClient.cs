using TinyUa.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Binary;
using TinyUa.Core.Security;
using TinyUa.Transport;
using TinyUa.Core.Types;
using TinyUa.Client.Services;
using TinyUa.Client.Subscriptions;

namespace TinyUa.Client.Connection
{
    internal class UaSocketClient : IDisposable
    {
        private readonly int _timeout;
        private readonly SecurityPolicy _securityPolicy;
        private readonly ConcurrentDictionary<uint, TaskCompletionSource<byte[]>> _callbacks;
        private readonly ConcurrentDictionary<uint, Func<byte[], Task>> _responseHandlers = new();
        private readonly ConcurrentDictionary<uint, Task> _startedHandlers = new();
        private readonly SecureConnection _connection;
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private readonly ILogger _logger;

        private static BinaryEncoder RentEncoder() => BinaryEncoderPool.Rent();

        private static void ReturnEncoder(BinaryEncoder e) => BinaryEncoderPool.Return(e);

        private Socket? _socket;
        private NetworkStream? _stream;
        private CancellationTokenSource? _receiveCts;
        private Task? _receiveTask;
        private volatile bool _running;
        private volatile bool _dead;
        private int _disposed;
        private Exception? _writeFailure;
        private uint _maxReceivePacketSize = 65536;
        private uint _requestId;
        private uint _revisedChannelLifetime;
        private long _lastRequestTicks = Environment.TickCount64;

        internal NodeId AuthenticationToken { get; set; }
        internal bool DebugMode { get; set; }
        internal uint RevisedChannelLifetime => _revisedChannelLifetime;

        internal UaSocketClient(int timeout = 1000, SecurityPolicy? securityPolicy = null, ILogger? logger = null)
        {
            _timeout = timeout;
            _securityPolicy = securityPolicy ?? new NoneSecurityPolicy();
            _callbacks = new ConcurrentDictionary<uint, TaskCompletionSource<byte[]>>();
            _connection = new SecureConnection(_securityPolicy);
            _logger = logger ?? NullLogger.Instance;
            AuthenticationToken = new NodeId();
            DebugMode = false;
            _revisedChannelLifetime = 3600000;
        }

        internal bool IsSecureChannelOpen => _connection.IsOpen;

        /// <summary>
        /// Milliseconds since the last request was written to the wire. Session lifetime is
        /// refreshed by every request the server receives, so this is the reference point for
        /// idle-gated session keep-alive.
        /// </summary>
        internal long IdleMilliseconds => Environment.TickCount64 - Volatile.Read(ref _lastRequestTicks);

        private void MarkRequestSent() => Volatile.Write(ref _lastRequestTicks, Environment.TickCount64);

        internal bool IsAlive => _running && _receiveTask != null && !_receiveTask.IsCompleted;

        internal event Action<Exception?>? ConnectionLost;

        internal async Task ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.NoDelay = true;

            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (_timeout > 0) deadline.CancelAfter(_timeout);
            try { await _socket.ConnectAsync(host, port, deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { throw new TimeoutException("TCP connection timed out."); }
            _stream = new NetworkStream(_socket, true);
        }

        private List<TaskCompletionSource<byte[]>> DrainCallbacksUnderSendLockSync()
        {
            bool got = _sendLock.Wait(TimeSpan.FromSeconds(2));
            try
            {
                var snapshot = new List<TaskCompletionSource<byte[]>>(_callbacks.Values);
                _callbacks.Clear();
                return snapshot;
            }
            finally { if (got) _sendLock.Release(); }
        }

        private async Task<List<TaskCompletionSource<byte[]>>> DrainCallbacksUnderSendLockAsync()
        {
            bool got = await _sendLock.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            try
            {
                var snapshot = new List<TaskCompletionSource<byte[]>>(_callbacks.Values);
                _callbacks.Clear();
                return snapshot;
            }
            finally { if (got) _sendLock.Release(); }
        }

        /// <summary>
        /// Writes a request while the caller owns <see cref="_sendLock"/>. Unsecured MSG frames
        /// are sent as [24-byte header, encoded body] with socket gather I/O, so the body is not
        /// copied into a transient full-frame array. The loop deliberately handles partial sends;
        /// TCP does not guarantee that a vectored send consumes every segment.
        /// </summary>
        private async Task<int> WriteMessageAsync(
            ArraySegment<byte> body, byte[] messageType, uint requestId, CancellationToken cancellationToken = default)
        {
            if (_dead)
                throw new SocketException((int)SocketError.ConnectionReset);

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (_timeout > 0) deadline.CancelAfter(_timeout);
            try
            {
                return await WriteMessageCoreAsync(body, messageType, requestId, deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                _writeFailure = new TimeoutException("Request write timed out.");
                CloseTransport();
                throw _writeFailure;
            }
            catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested)
            {
                _writeFailure = ex;
                CloseTransport();
                throw new OperationCanceledException("Request write cancelled.", ex, cancellationToken);
            }
            catch (UaException ex) when (ex.StatusCode == 0x80B80000) { throw; }
            catch (Exception ex) { _writeFailure = ex; CloseTransport(); throw; }
        }

        private async Task<int> WriteMessageCoreAsync(ArraySegment<byte> body, byte[] messageType, uint requestId, CancellationToken cancellationToken)
        {

            using var header = BufferLease.Rent(24);
            if (_connection.TryWriteUnsecuredMessageHeader(body, messageType, requestId, header.CapacitySpan))
            {
                header.Length = 24;
                await SendSegmentsAsync(header.Segment, body, cancellationToken).ConfigureAwait(false);
                return 24 + body.Count;
            }

            var chunks = _connection.CreateMessageChunks(body, messageType, requestId);
            var total = 0;
            try
            {
                foreach (var chunk in chunks)
                {
                    using var message = chunk.ToBufferLease();
                    await _stream!.WriteAsync(message.Array, 0, message.Length, cancellationToken).ConfigureAwait(false);
                    total += message.Length;
                }
                return total;
            }
            finally
            {
                foreach (var chunk in chunks)
                    if (!ReferenceEquals(chunk.Body, body.Array))
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(chunk.Body);
            }
        }

        private async Task SendSegmentsAsync(
            ArraySegment<byte> first, ArraySegment<byte> second, CancellationToken cancellationToken)
        {
            var socket = _socket ?? throw new InvalidOperationException("Socket is not connected");
            // The gather-send overload has no cancellation support on .NET 8. For
            // cancellable handshakes use the memory overload and await actual I/O completion
            // before returning any pooled header/body buffers.
            if (cancellationToken.CanBeCanceled)
            {
                foreach (var segment in new[] { first, second })
                {
                    var remaining = segment.AsMemory();
                    while (!remaining.IsEmpty)
                    {
                        var sent = await socket.SendAsync(remaining, SocketFlags.None, cancellationToken)
                            .ConfigureAwait(false);
                        if (sent <= 0)
                            throw new SocketException((int)SocketError.ConnectionReset);
                        remaining = remaining.Slice(sent);
                    }
                }
                return;
            }
            var segments = new List<ArraySegment<byte>>(2) { first, second };

            while (segments.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int sent = await socket.SendAsync((IList<ArraySegment<byte>>)segments, SocketFlags.None)
                    .ConfigureAwait(false);
                if (sent <= 0)
                    throw new SocketException((int)SocketError.ConnectionReset);

                while (sent > 0 && segments.Count > 0)
                {
                    var current = segments[0];
                    if (sent >= current.Count)
                    {
                        sent -= current.Count;
                        segments.RemoveAt(0);
                    }
                    else
                    {
                        segments[0] = new ArraySegment<byte>(
                            current.Array!, current.Offset + sent, current.Count - sent);
                        sent = 0;
                    }
                }
            }
        }

        private void CloseTransport()
        {
            _dead = true;
            _running = false;
            try { _receiveCts?.Cancel(); } catch (ObjectDisposedException) { }

            try { _socket?.Shutdown(SocketShutdown.Both); } catch (Exception ex) { _logger.LogDebug(ex, "Socket shutdown (ignored)"); }

            _stream?.Close();
            _stream = null;
            _socket?.Close();
            _socket = null;
        }

        /// <summary>Synchronous disconnect for Dispose paths. Does not wait for the receive loop to exit.</summary>
        internal void Disconnect()
        {
            CloseTransport();
            _receiveTask = null;

            var toCancel = DrainCallbacksUnderSendLockSync();
            foreach (var cb in toCancel)
                cb.TrySetCanceled();
        }

        internal async Task DisconnectAsync()
        {
            CloseTransport();

            var receiveTask = _receiveTask;
            if (receiveTask != null && !receiveTask.IsCompleted)
            {
                try { await receiveTask.ConfigureAwait(false); } catch { }
            }
            _receiveTask = null;

            var toCancel = await DrainCallbacksUnderSendLockAsync().ConfigureAwait(false);
            foreach (var cb in toCancel)
                cb.TrySetCanceled();
        }

        internal async Task RetirePolicyAsync(SecurityPolicy policy)
        {
            await DisconnectAsync().ConfigureAwait(false);
            await _sendLock.WaitAsync().ConfigureAwait(false);
            try { policy.Dispose(); }
            finally { _sendLock.Release(); }
        }

        internal void SimulateReceiveLoopExit()
        {
            _dead = true;
            _running = false;
            var toFault = DrainCallbacksUnderSendLockSync();
            var ex = new SocketException((int)SocketError.ConnectionReset);
            foreach (var cb in toFault)
                cb.TrySetException(ex);
        }

        internal bool IsDead => _dead;

        internal async Task<Acknowledge> SendHelloAsync(string endpointUrl, uint maxMessageSize = 0,
            uint maxChunkCount = 0, CancellationToken cancellationToken = default)
        {
            var hello = new Hello
            {
                EndpointUrl = endpointUrl,
                MaxMessageSize = maxMessageSize,
                MaxChunkCount = maxChunkCount
            };

            var encoder = RentEncoder();
            try
            {
                hello.Encode(encoder);
                var body = encoder.GetBuffer();
                using var header = BufferLease.Rent(8);
                var bytes = header.Array;
                bytes[0] = MessageType.Hello[0];
                bytes[1] = MessageType.Hello[1];
                bytes[2] = MessageType.Hello[2];
                bytes[3] = ChunkType.Single;
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), (uint)(8 + body.Count));
                header.Length = 8;

                _logger.LogDebug($"Sending Hello: {header.Length + body.Count} bytes");
                using var writeCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (_timeout > 0) writeCancellation.CancelAfter(_timeout);
                try
                {
                    await SendSegmentsAsync(header.Segment, body, writeCancellation.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException("Hello write operation timed out");
                }
            }
            finally
            {
                ReturnEncoder(encoder);
            }

            using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (_timeout > 0) readDeadline.CancelAfter(_timeout);
            Header responseHeader;
            try { responseHeader = await ReadHeaderDirectAsync(readDeadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { throw new TimeoutException("Hello response header read timed out"); }

            _logger.LogDebug($"Received response header: {responseHeader}");

            if ((!responseHeader.IsAcknowledge && !responseHeader.IsError)
                || responseHeader.ChunkType != ChunkType.Single
                || responseHeader.BodySize < 0 || responseHeader.BodySize > 65528
                || (responseHeader.IsAcknowledge && responseHeader.BodySize != 20))
                throw new UaException(0x80800000, "Invalid Hello response header or length.");
            var responseBody = new byte[responseHeader.BodySize];
            var read = 0;
            while (read < responseBody.Length)
            {
                int bytesRead;
                try { bytesRead = await _stream!.ReadAsync(responseBody.AsMemory(read), readDeadline.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                { throw new TimeoutException("Hello response body read timed out"); }
                if (bytesRead == 0) throw new EndOfStreamException("Peer closed during Hello response body.");
                read += bytesRead;
            }

            if (responseHeader.IsAcknowledge)
            {
                var decoder = new BinaryDecoder(responseBody);
                var ack = Acknowledge.Decode(decoder);
                if (ack.SendBufferSize < 8192) throw new UaException(0x80810000, "Invalid server send buffer size.");
                _maxReceivePacketSize = Math.Min(hello.ReceiveBufferSize, ack.SendBufferSize);
                _connection.ApplyAcknowledge(ack, hello.SendBufferSize);
                _connection.SetReceiveLimits(maxMessageSize, maxChunkCount);
                _logger.LogDebug($"Hello acknowledged: receiveBuffer={ack.ReceiveBufferSize}, sendBuffer={ack.SendBufferSize}, maxMessage={ack.MaxMessageSize}, maxChunks={ack.MaxChunkCount}");
                StartReceiveLoop();
                return ack;
            }

            if (responseHeader.IsError)
            {
                var decoder = new BinaryDecoder(responseBody);
                var error = ErrorMessage.Decode(decoder);
                throw new UaException(error.Error.Value, error.Reason ?? "Unknown error");
            }

            throw new UaException(0x80000000, "Unexpected response to Hello");
        }

        private async Task<Header> ReadHeaderDirectAsync(CancellationToken cancellationToken = default)
        {
            if (_stream == null)
                throw new InvalidOperationException("Socket is not connected");

            var headerBuffer = new byte[8];
            var read = 0;
            while (read < 8)
            {
                var bytesRead = await _stream!.ReadAsync(headerBuffer, read, 8 - read, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) throw new EndOfStreamException("Peer closed during Hello response header.");
                read += bytesRead;
            }

            var decoder = new BinaryDecoder(headerBuffer);
            return Header.Decode(decoder);
        }

        internal async Task<OpenSecureChannelResult> OpenSecureChannelAsync(OpenSecureChannelParameters parameters,
            CancellationToken cancellationToken = default)
        {
            var request = new OpenSecureChannelRequest
            {
                Parameters = parameters
            };

            _logger.LogDebug("Sending OpenSecureChannel request...");

            var response = await SendRequestAsync(request, MessageType.SecureOpen, cancellationToken);

            _logger.LogDebug($"Received OpenSecureChannel response: {response.Length} bytes");

            var decoder = new BinaryDecoder(response);
            var result = OpenSecureChannelResponse.Decode(decoder);

            result.ResponseHeader.ServiceResult.Check();

            _connection.SetChannel(result.Parameters.SecurityToken, parameters.RequestType, parameters.ClientNonce, result.Parameters.ServerNonce);

            if (parameters.RequestType == SecurityTokenRequestType.Renew)
            {
                _connection.RevolveTokens();
            }

            _revisedChannelLifetime = result.Parameters.SecurityToken.RevisedLifetime;

            _logger.LogDebug($"Channel Token RevisedLifetime: {_revisedChannelLifetime}ms");

            return result.Parameters;
        }

        private void StartReceiveLoop()
        {
            if (_receiveTask != null) return;

            _running = true;
            _dead = false;
            _receiveCts = new CancellationTokenSource();

            _receiveTask = ReceiveLoopAsync(_receiveCts.Token);
        }

        internal async Task<byte[]> SendRequestAsync<T>(T request, byte[]? messageType = null, CancellationToken cancellationToken = default) where T : IEncodable
        {
            cancellationToken.ThrowIfCancellationRequested();
            messageType ??= MessageType.SecureMessage;

            var encoder = RentEncoder();
            try { request.Encode(encoder); }
            catch { ReturnEncoder(encoder); throw; }

            var bodySegment = encoder.GetBuffer();

            bool debugEnabled;
            try
            {
                debugEnabled = _logger.IsEnabled(LogLevel.Debug);
                if (debugEnabled) _logger.LogDebug($"Request {typeof(T).Name}: {bodySegment.Count} encoded bytes");
            }
            catch { ReturnEncoder(encoder); throw; }

            var requestId = Interlocked.Increment(ref _requestId);
            // RunContinuationsAsynchronously is the safe default for a public SDK: the receive
            // loop calls TrySetResult, and we cannot assume the awaiter's continuation (which may
            // chain into user code via subscriptions, callbacks, etc.) is trivial or lock-free.
            // Inline continuation (TaskCreationOptions.None) is faster — ~10-30μs saved per
            // request by skipping a ThreadPool dispatch — but risks stack dives, reentrancy, and
            // deadlocks if any future feature runs non-trivial code on the completion path.
            // TinyUa targets broad reuse, so we prefer stability over microsecond-level latency
            // and stay consistent with SendEncodedBodyAsync below.
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

            try
            {
                if (!await _sendLock.WaitAsync(_timeout > 0 ? _timeout : Timeout.Infinite, cancellationToken).ConfigureAwait(false))
                    throw new TimeoutException("Timed out waiting for send lock");
            }
            catch
            {
                ReturnEncoder(encoder);
                throw;
            }
            try
            {
                if (_stream == null)
                    throw new InvalidOperationException("Socket is not connected");

                if (!MessageType.Equals(messageType, MessageType.SecureOpen))
                {
                    if (_connection.NextSecurityToken.TokenId != 0)
                    {
                        _connection.RevolveTokens();
                    }
                }

                if (debugEnabled)
                    _logger.LogDebug($"Connection state: ChannelId={_connection.SecurityToken.ChannelId}, TokenId={_connection.SecurityToken.TokenId}");

                // Install the correlation before writing: a local server can answer before the
                // asynchronous send operation resumes.
                _callbacks[requestId] = tcs;
                var messageLength = await WriteMessageAsync(bodySegment, messageType, (uint)requestId, cancellationToken)
                    .ConfigureAwait(false);

                if (debugEnabled)
                    _logger.LogDebug($"Sending request {requestId}: {messageLength} bytes");

                if (MessageType.Equals(messageType, MessageType.SecureMessage)) MarkRequestSent();
            }
            catch
            {
                _callbacks.TryRemove(requestId, out _);
                tcs.TrySetCanceled();
                throw;
            }
            finally
            {
                _sendLock.Release();
                ReturnEncoder(encoder);
            }

            try
            {
                return await WaitWithTimeoutAsync(tcs.Task,
                    $"Request {requestId} response timed out", cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _callbacks.TryRemove(requestId, out _);
                _logger.LogWarning($"Request {requestId} TIMED OUT — IsAlive={IsAlive}, pending callbacks={_callbacks.Count}");
                throw;
            }
            catch (OperationCanceledException)
            {
                _callbacks.TryRemove(requestId, out _);
                throw;
            }
        }

        private async Task<T> WaitWithTimeoutAsync<T>(Task<T> task, string errorMessage,
            CancellationToken cancellationToken)
        {
            if (_timeout <= 0)
                return await task.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                return await task.WaitAsync(TimeSpan.FromMilliseconds(_timeout), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(errorMessage);
            }
        }

        /// <summary>
        /// Sends a request without awaiting the response. Completion contract: if this method
        /// throws synchronously, neither callback fires; if it returns, exactly one of
        /// <paramref name="callback"/> (response received) or <paramref name="onError"/>
        /// (request faulted/cancelled, e.g. on disconnect) eventually fires.
        /// </summary>
        internal async Task SendRequestNoWait<T>(T request, Func<byte[], Task>? callback = null, byte[]? messageType = null, Action<Exception>? onError = null, TimeSpan? responseTimeout = null) where T : IEncodable
        {
            messageType ??= MessageType.SecureMessage;

            var enc = RentEncoder();
            try { request.Encode(enc); }
            catch { ReturnEncoder(enc); throw; }
            var bodySegment = enc.GetBuffer();

            var requestId = Interlocked.Increment(ref _requestId);
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

            // WaitAsync(TimeSpan) returns false on timeout instead of throwing. Ignoring it would
            // let us send without the lock AND over-release the semaphore in finally, permanently
            // breaking send mutual exclusion.
            bool acquired;
            try { acquired = await _sendLock.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false); }
            catch { ReturnEncoder(enc); throw; }
            if (!acquired)
            {
                ReturnEncoder(enc);
                throw new TimeoutException("Timed out waiting for send lock");
            }
            try
            {
                if (_stream == null)
                    throw new InvalidOperationException("Socket is not connected");

                if (!MessageType.Equals(messageType, MessageType.SecureOpen))
                {
                    if (_connection.NextSecurityToken.TokenId != 0)
                    {
                        _connection.RevolveTokens();
                    }
                }

                if (callback != null || onError != null)
                {
                    _responseHandlers[requestId] = callback ?? (_ => Task.CompletedTask);
                    _callbacks[requestId] = tcs;
                }

                await WriteMessageAsync(bodySegment, messageType, (uint)requestId).ConfigureAwait(false);
                if (MessageType.Equals(messageType, MessageType.SecureMessage)) MarkRequestSent();
            }
            catch (Exception)
            {
                if ((callback == null && onError == null) || _callbacks.TryRemove(requestId, out _))
                {
                    _responseHandlers.TryRemove(requestId, out _);
                    throw;
                }
                // The receiver or disconnect already owns completion. Let the watcher report
                // that outcome exactly once, even if the send continuation observes a failure.
            }
            finally
            {
                _sendLock.Release();
                ReturnEncoder(enc);
            }

            // Hook the watcher only after a successful send, so a synchronous failure above never
            // races a callback. A response that already arrived just completes the awaited task.
            if (callback != null || onError != null)
            {
                InvokeCallbackAsync(tcs.Task, callback, onError, responseTimeout, (uint)requestId).Forget(_logger, nameof(InvokeCallbackAsync));
            }
        }

        private async Task InvokeCallbackAsync(Task<byte[]> task, Func<byte[], Task>? callback, Action<Exception>? onError, TimeSpan? responseTimeout, uint requestId)
        {
            try
            {
                try
                {
                    if (responseTimeout is { } timeout) await task.WaitAsync(timeout).ConfigureAwait(false);
                    else await task.ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    if (_callbacks.TryRemove(requestId, out _)) throw;
                    // Receive or disconnect already owns completion. Observe that outcome,
                    // including a disconnect fault racing the response deadline.
                    await task.ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _responseHandlers.TryRemove(requestId, out _);
                try { onError?.Invoke(ex); }
                catch (Exception callbackError) { _logger.LogError(callbackError, "Request error callback failed"); }
                return;
            }

            try
            {
                if (_startedHandlers.TryRemove(requestId, out var started))
                    await started.ConfigureAwait(false);
            }
            catch (Exception ex) { _logger.LogError(ex, "Request response callback failed"); }
        }
        internal async Task<TResponse> SendRequestAsync<TRequest, TResponse>(TRequest request, byte[]? messageType = null)
            where TRequest : IEncodable
            where TResponse : IDecodable<TResponse>
        {
            var body = await SendRequestAsync(request, messageType);
            var decoder = new BinaryDecoder(body);
            return TResponse.Decode(decoder);
        }

        internal async Task<byte[]> SendEncodedBodyAsync(byte[] encodedBody, byte[]? messageType = null)
        {
            messageType ??= MessageType.SecureMessage;

            var requestId = Interlocked.Increment(ref _requestId);
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

            if (!await _sendLock.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false))
                throw new TimeoutException("Timed out waiting for send lock");
            try
            {
                if (!MessageType.Equals(messageType, MessageType.SecureOpen))
                {
                    if (_connection.NextSecurityToken.TokenId != 0)
                        _connection.RevolveTokens();
                }
                _callbacks[requestId] = tcs;

                await WriteMessageAsync(new ArraySegment<byte>(encodedBody), messageType, (uint)requestId)
                    .ConfigureAwait(false);
                MarkRequestSent();
            }
            catch
            {
                _callbacks.TryRemove(requestId, out _);
                tcs.TrySetCanceled();
                throw;
            }
            finally
            {
                _sendLock.Release();
            }

            try
            {
                return await tcs.Task.WithTimeout(_timeout, $"Request {requestId} response timed out").ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _callbacks.TryRemove(requestId, out _);
                _logger.LogWarning($"Request {requestId} TIMED OUT — IsAlive={IsAlive}, pending callbacks={_callbacks.Count}");
                throw;
            }
        }

        private async Task ReceiveLoopAsync(CancellationToken ct)
        {
            _logger.LogDebug("Receive loop started (buffered)");
            Exception? exitException = null;

            // A single pooled buffer holds all bytes read but not yet parsed. One ReadAsync
            // pulls as much data as the kernel has ready (commonly several messages at once),
            // and we drain every complete message from the buffer before asking for more.
            // This replaces the previous pattern of one ReadAsync per header (8B), one per
            // channel id (4B) and one per body — at least three syscalls per message — with
            // a single buffered read, while keeping the zero-external-dependency story intact
            // (System.IO.Pipelines is not part of the net8.0 NETCore.App shared framework).
            const int normalReceiveBufferSize = 8192;
            const int maxRetainedReceiveBufferSize = 256 * 1024;
            byte[] buf = BufferLease.RentSharedArray(normalReceiveBufferSize);
            int len = 0;   // count of valid bytes in buf
            int pos = 0;   // parse cursor; bytes [0, pos) are already consumed
            long partialStarted = 0;

            try
            {
                var debugEnabled = _logger.IsEnabled(LogLevel.Debug);

                while (_running && !ct.IsCancellationRequested)
                {
                    // Compact already-parsed bytes out of the front so the next read has room
                    // in the tail. Array.Copy is documented to behave correctly when source
                    // and destination overlap.
                    if (pos > 0)
                    {
                        if (pos < len)
                            Array.Copy(buf, pos, buf, 0, len - pos);
                        len -= pos;
                        pos = 0;
                    }

                    // A single large but valid frame may grow the connection ring into the LOH.
                    // Once it has been fully consumed, return to the normal steady-state size so
                    // one historical response cannot inflate this connection indefinitely.
                    if (len == 0 && buf.Length > maxRetainedReceiveBufferSize)
                    {
                        BufferLease.ReturnSharedArray(buf);
                        buf = BufferLease.RentSharedArray(normalReceiveBufferSize);
                    }

                    // Pull more data from the socket whenever there is room.
                    if (len < buf.Length)
                    {
                        int n;
                        try
                        {
                            // Bound total assembly time, not time since the latest byte.
                            // Idle sessions with no partial frame have no receive deadline.
                            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            if (len > 0)
                            {
                                var remaining = 60000 - (Environment.TickCount64 - partialStarted);
                                if (remaining <= 0) throw new TimeoutException("Partial frame assembly timed out.");
                                deadline.CancelAfter(TimeSpan.FromMilliseconds(remaining));
                            }
                            n = await _stream!.ReadAsync(buf.AsMemory(len, buf.Length - len), deadline.Token)
                                .ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested)
                        {
                            _logger.LogDebug("Receive loop cancelled");
                            break;
                        }
                        catch (OperationCanceledException)
                        {
                            throw new TimeoutException("Partial frame assembly timed out.");
                        }

                        if (n == 0)
                        {
                            // Remote end sent FIN. Any trailing bytes are an incomplete message.
                            if (len > 0)
                                _logger.LogWarning($"Receive loop: stream closed by remote (FIN received) with {len} bytes trailing");
                            else
                                _logger.LogWarning("Receive loop: stream closed by remote (FIN received)");
                            break;
                        }

                        len += n;
                    }

                    // Drain every complete message currently buffered. TryParseMessage returns
                    // false (leaving pos untouched) when only a partial message remains.
                    while (TryParseMessage(buf, pos, len, out int msgLen, out var header, out ArraySegment<byte> body))
                    {
                        if (debugEnabled)
                        {
                            _logger.LogDebug($"Received header: {header}");
                            _logger.LogDebug($"Received body: {body.Count} bytes");
                        }

                        object? message;
                        try
                        {
                            message = _connection.ReceiveFromHeaderAndBody(header!, body);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, $"Receive loop: message parsing failed (header={header}), closing channel");

                            // A failed authentication/framing check invalidates this channel.
                            // Encrypted bytes cannot be used to infer a trustworthy request ID.
                            throw;
                        }

                        if (debugEnabled)
                            _logger.LogDebug($"Parsed message: {message?.GetType().Name ?? "null"}");

                        if (message is Message msg)
                        {
                            if (debugEnabled)
                                _logger.LogDebug($"Message RequestId: {msg.RequestId}");

                            if (_callbacks.TryRemove(msg.RequestId, out var tcs))
                            {
                                // Invoke the dispatch entry points in wire order. Only awaiters
                                // run asynchronously; the receive loop never waits on user work.
                                if (_responseHandlers.TryRemove(msg.RequestId, out var handler))
                                {
                                    try { _startedHandlers[msg.RequestId] = handler(msg.Body); }
                                    catch (Exception ex) { _startedHandlers[msg.RequestId] = Task.FromException(ex); }
                                }
                                tcs.TrySetResult(msg.Body);
                            }
                            else if (debugEnabled)
                            {
                                _logger.LogDebug($"No callback found for request {msg.RequestId}");
                            }
                        }
                        else if (message is ErrorMessage err)
                        {
                            _logger.LogWarning($"Error message received: StatusCode=0x{err.Error.Value:X8}, Reason={err.Reason}");

                            throw new UaException(err.Error.Value,
                                $"Server ErrorMessage: Code=0x{err.Error.Value:X8}, Reason={err.Reason ?? "(null)"}");
                        }

                        pos += msgLen;
                        partialStarted = 0;
                    }
                    if (len > pos && partialStarted == 0) partialStarted = Environment.TickCount64;

                    // If the buffer is full but we still couldn't parse a complete message,
                    // grow it so the next read can accommodate the rest of the partial message.
                    if (pos == 0 && len == buf.Length)
                    {
                        var grown = BufferLease.RentSharedArray(buf.Length * 2);
                        Buffer.BlockCopy(buf, 0, grown, 0, len);
                        BufferLease.ReturnSharedArray(buf);
                        buf = grown;
                    }
                }
            }
            catch (Exception ex)
            {
                exitException = ex;
                _logger.LogWarning(ex, "Receive loop exiting due to exception — socket is now dead");
            }
            finally
            {
                BufferLease.ReturnSharedArray(buf);

                var unexpectedExit = _running || _writeFailure != null;
                exitException ??= _writeFailure;

                _running = false;
                _dead = true;
                CloseTransport();

                var toFault = await DrainCallbacksUnderSendLockAsync().ConfigureAwait(false);
                if (toFault.Count > 0)
                {
                    var faultEx = exitException ?? new SocketException((int)SocketError.ConnectionReset);
                    foreach (var cb in toFault)
                        cb.TrySetException(faultEx);
                    _logger.LogWarning($"Receive loop exited — faulted {toFault.Count} pending callbacks");
                }

                if (unexpectedExit)
                {
                    var lostEx = exitException ?? new SocketException((int)SocketError.ConnectionReset);
                    try { ConnectionLost?.Invoke(lostEx); }
                    catch (Exception evEx) { _logger.LogError(evEx, "ConnectionLost event handler threw"); }
                }
                _receiveCts?.Dispose();
            }
        }

        /// <summary>
        /// Attempts to parse one complete message from the front of the receive buffer
        /// <paramref name="buf"/> starting at offset <paramref name="pos"/> (with <paramref name="len"/>
        /// valid bytes total). On success, returns the decoded <see cref="Header"/>, a freshly
        /// borrowed body segment and the total number of bytes consumed in
        /// <paramref name="msgLen"/>. Returns false (without modifying the caller's cursor) when
        /// the buffer does not yet hold a full message, so the caller can request more data from
        /// the socket.
        /// </summary>
        private bool TryParseMessage(byte[] buf, int pos, int len,
            out int msgLen, out Header? header, out ArraySegment<byte> body)
        {
            msgLen = 0;
            header = null;
            body = default;

            int available = len - pos;
            if (available < 8)
                return false;

            // Header field: PacketSize is the little-endian uint32 at offset 4 from the frame start.
            uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(pos + 4, 4));

            // Guard against malformed/adversarial sizes BEFORE the "need more data" check, so a
            // bad frame is rejected immediately rather than forcing the buffer to grow unbounded.
            const int MaxPacketSize = 8 + 4 + 16 * 1024 * 1024; // header + channelId + 16 MiB body
            if (packetSize < 8 || packetSize > MaxPacketSize || packetSize > _maxReceivePacketSize)
                throw new InvalidOperationException($"Invalid PacketSize: {packetSize}");

            // Wait until the entire message (header + channel id + body) is buffered.
            if (available < packetSize)
                return false;

            var msgType = ResolveMessageType(buf[pos], buf[pos + 1], buf[pos + 2]);
            byte chunkType = buf[pos + 3];
            bool isSecure = MessageType.Equals(msgType, MessageType.SecureMessage)
                         || MessageType.Equals(msgType, MessageType.SecureOpen)
                         || MessageType.Equals(msgType, MessageType.SecureClose);

            int bodySize = (int)packetSize - 8;
            long offset = 8;
            uint channelId = 0;
            if (isSecure)
            {
                if (packetSize < 12)
                    throw new InvalidOperationException($"Invalid PacketSize for secure message: {packetSize} (minimum 12)");
                bodySize -= 4; // the 4-byte channel id is not part of BodySize
                channelId = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(pos + 8, 4));
                offset = 12;
            }

            const int MaxBodySize = 16 * 1024 * 1024;
            if (bodySize < 0 || bodySize > MaxBodySize)
                throw new InvalidOperationException($"Invalid BodySize: {bodySize}");

            header = new Header
            {
                MessageType = msgType,
                ChunkType = chunkType,
                PacketSize = packetSize,
                BodySize = bodySize,
                ChannelId = channelId
            };

            body = new ArraySegment<byte>(buf, pos + (int)offset, bodySize);

            msgLen = (int)packetSize;
            return true;
        }

        private static byte[] ResolveMessageType(byte first, byte second, byte third)
        {
            // All normal OPC UA TCP message types are shared immutable three-byte constants.
            // Reusing them removes one allocation from every received frame.
            if (first == (byte)'M' && second == (byte)'S' && third == (byte)'G') return MessageType.SecureMessage;
            if (first == (byte)'O' && second == (byte)'P' && third == (byte)'N') return MessageType.SecureOpen;
            if (first == (byte)'C' && second == (byte)'L' && third == (byte)'O') return MessageType.SecureClose;
            if (first == (byte)'H' && second == (byte)'E' && third == (byte)'L') return MessageType.Hello;
            if (first == (byte)'A' && second == (byte)'C' && third == (byte)'K') return MessageType.Acknowledge;
            if (first == (byte)'E' && second == (byte)'R' && third == (byte)'R') return MessageType.Error;
            if (first == (byte)'I' && second == (byte)'N' && third == (byte)'V') return MessageType.Invalid;
            return new[] { first, second, third };
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            Disconnect();
            // SemaphoreSlim has no native handle unless AvailableWaitHandle is used. Leave it
            // to GC: asynchronous send/fault continuations may still release it after Dispose.
            // Cancelled ReadAsync is awaited by the receive loop before returning its buffer.
        }
    }
}
