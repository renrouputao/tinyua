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

        internal bool IsAlive => Volatile.Read(ref _running) && _receiveTask != null && !_receiveTask.IsCompleted;

        internal event Action<Exception?>? ConnectionLost;

        internal async Task ConnectAsync(string host, int port)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.NoDelay = true;

            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);

            await _socket.ConnectAsync(host, port);
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

        private void FaultAllCallbacks(Exception exception)
        {
            // An ERR frame is terminal for every outstanding request. Removing entries before
            // completing them prevents stale callbacks from accumulating until a later close.
            foreach (var pair in _callbacks)
            {
                if (_callbacks.TryRemove(pair.Key, out var callback))
                    callback.TrySetException(exception);
            }
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

            using var header = BufferLease.Rent(24);
            if (_connection.TryWriteUnsecuredMessageHeader(body, messageType, requestId, header.CapacitySpan))
            {
                header.Length = 24;
                await SendSegmentsAsync(header.Segment, body, cancellationToken).ConfigureAwait(false);
                return 24 + body.Count;
            }

            var chunks = _connection.CreateMessageChunks(body, messageType, requestId);
            var total = 0;
            foreach (var chunk in chunks)
            {
                using var message = chunk.ToBufferLease();
                await _stream!.WriteAsync(message.Array, 0, message.Length, cancellationToken).ConfigureAwait(false);
                total += message.Length;
            }
            return total;
        }

        private async Task SendSegmentsAsync(
            ArraySegment<byte> first, ArraySegment<byte> second, CancellationToken cancellationToken)
        {
            var socket = _socket ?? throw new InvalidOperationException("Socket is not connected");
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
            _receiveCts?.Cancel();

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
                try { await receiveTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
            }
            _receiveTask = null;

            var toCancel = await DrainCallbacksUnderSendLockAsync().ConfigureAwait(false);
            foreach (var cb in toCancel)
                cb.TrySetCanceled();
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

        internal async Task<Acknowledge> SendHelloAsync(string endpointUrl, uint maxMessageSize = 0, uint maxChunkCount = 0)
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
                await SendSegmentsAsync(header.Segment, body, CancellationToken.None)
                    .WithTimeout(_timeout, "Hello write operation timed out");
            }
            finally
            {
                ReturnEncoder(encoder);
            }

            var responseHeaderTask = ReadHeaderDirectAsync();
            var responseHeader = await responseHeaderTask.WithTimeout(_timeout, "Hello response header read timed out");

            _logger.LogDebug($"Received response header: {responseHeader}");

            var responseBody = new byte[responseHeader.BodySize];
            var read = 0;
            while (read < responseBody.Length)
            {
                var readTask = _stream.ReadAsync(responseBody, read, responseBody.Length - read);
                var bytesRead = await readTask.WithTimeout(_timeout, "Hello response body read timed out");
                read += bytesRead;
            }

            if (responseHeader.IsAcknowledge)
            {
                var decoder = new BinaryDecoder(responseBody);
                var ack = Acknowledge.Decode(decoder);
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

        private async Task<Header> ReadHeaderDirectAsync()
        {
            if (_stream == null)
                throw new InvalidOperationException("Socket is not connected");

            var headerBuffer = new byte[8];
            var read = 0;
            while (read < 8)
            {
                read += await _stream!.ReadAsync(headerBuffer, read, 8 - read);
            }

            var decoder = new BinaryDecoder(headerBuffer);
            return Header.Decode(decoder);
        }

        internal async Task<OpenSecureChannelResult> OpenSecureChannelAsync(OpenSecureChannelParameters parameters)
        {
            var request = new OpenSecureChannelRequest
            {
                Parameters = parameters
            };

            _logger.LogDebug("Sending OpenSecureChannel request...");

            var response = await SendRequestAsync(request, MessageType.SecureOpen);

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
            messageType ??= MessageType.SecureMessage;

            var encoder = RentEncoder();
            request.Encode(encoder);

            var bodySegment = encoder.GetBuffer();

            var debugEnabled = _logger.IsEnabled(LogLevel.Debug);
            if (debugEnabled)
            {
                // Cap the hex dump — a full dump of a large body builds a 3x-length string.
                var dumpLen = Math.Min(bodySegment.Count, 256);
                var suffix = bodySegment.Count > dumpLen ? $" ... ({bodySegment.Count} bytes total)" : "";
                _logger.LogDebug($"Request body ({bodySegment.Count} bytes): {BitConverter.ToString(bodySegment.Array!, bodySegment.Offset, dumpLen).Replace("-", " ")}{suffix}");
            }

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

            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
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
                ReturnEncoder(encoder);
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
            request.Encode(enc);
            var bodySegment = enc.GetBuffer();

            var requestId = Interlocked.Increment(ref _requestId);
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

            // WaitAsync(TimeSpan) returns false on timeout instead of throwing. Ignoring it would
            // let us send without the lock AND over-release the semaphore in finally, permanently
            // breaking send mutual exclusion.
            if (!await _sendLock.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false))
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

                _callbacks[requestId] = tcs;

                await WriteMessageAsync(bodySegment, messageType, (uint)requestId).ConfigureAwait(false);
                MarkRequestSent();
            }
            catch (Exception)
            {
                _callbacks.TryRemove(requestId, out _);
                throw;
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
            byte[] result;
            try
            {
                // When a response timeout is requested (e.g. for Publish long-polls), bound the
                // wait so a silently-dropped response cannot pin an in-flight slot forever. The
                // underlying tcs stays in _callbacks until either the response arrives (TrySetResult
                // is a no-op on the already-timed-out wrapper) or the timeout handler removes it.
                if (responseTimeout is { } timeout)
                    result = await task.WaitAsync(timeout).ConfigureAwait(false);
                else
                    result = await task.ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // Release the callback slot so a late response doesn't try to complete an already-
                // abandoned tcs (TrySetResult would be a no-op anyway, but this frees the entry for
                // GC and avoids a "no callback found" debug log on the receive loop). Then surface
                // the timeout via onError so the caller can release its in-flight slot / retry.
                _callbacks.TryRemove(requestId, out _);
                var ts = responseTimeout!.Value;
                if (onError != null)
                {
                    try { onError(new TimeoutException($"No response for request {requestId} within {ts.TotalSeconds:F0}s")); }
                    catch (Exception cbEx) { _logger.LogError(cbEx, "SendRequestNoWait error callback failed (timeout)"); }
                }
                else
                {
                    _logger.LogDebug($"SendRequestNoWait request {requestId} timed out after {ts.TotalSeconds:F0}s (no error callback)");
                }
                return;
            }
            catch (Exception ex)
            {
                if (onError != null)
                {
                    try { onError(ex); }
                    catch (Exception cbEx) { _logger.LogError(cbEx, "SendRequestNoWait error callback failed"); }
                }
                else
                {
                    _logger.LogDebug(ex, "SendRequestNoWait request faulted (no error callback)");
                }
                return;
            }

            try
            {
                if (callback != null)
                    await callback(result).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SendRequestNoWait callback failed");
            }
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
                            // Apply a receive deadline: if no bytes arrive within 60s the peer is
                            // either dead or slow-drip-feeding partial frames to keep the loop
                            // alive. TCP keepalive catches fully dead sockets (~25s), but a
                            // drip-feed attacker keeps the TCP connection alive while starving
                            // the application layer. Closing the socket forces reconnect.
                            n = await _stream!.ReadAsync(buf, len, buf.Length - len, ct)
                                .WaitAsync(TimeSpan.FromSeconds(60), ct)
                                .ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            _logger.LogDebug("Receive loop cancelled");
                            break;
                        }
                        catch (TimeoutException)
                        {
                            _logger.LogWarning("Receive loop: no data for 60s, closing connection (possible slow-drip or dead peer)");
                            break;
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
                            _logger.LogWarning(ex, $"Receive loop: message parsing failed (header={header}), attempting to fault callback and continue");

                            if (header!.IsSecureMessage && body.Count >= 12)
                            {
                                try
                                {
                                    var reqId = BinaryPrimitives.ReadUInt32LittleEndian(body.Array!.AsSpan(body.Offset + 8, 4));
                                    if (_callbacks.TryRemove(reqId, out var tcs))
                                    {
                                        tcs.TrySetException(ex);
                                        if (debugEnabled)
                                            _logger.LogDebug($"Faulted callback for request {reqId} after parse failure");
                                    }
                                }
                                catch { }
                            }
                            else
                            {
                                FaultAllCallbacks(ex);
                            }

                            // The frame was parsed off the wire; advance past it so we do not
                            // retry the same bad message forever.
                            pos += msgLen;
                            continue;
                        }

                        if (debugEnabled)
                            _logger.LogDebug($"Parsed message: {message?.GetType().Name ?? "null"}");

                        if (message is Message msg)
                        {
                            if (debugEnabled)
                                _logger.LogDebug($"Message RequestId: {msg.RequestId}");

                            if (_callbacks.TryRemove(msg.RequestId, out var tcs))
                            {
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

                            FaultAllCallbacks(new UaException(err.Error.Value,
                                $"Server ErrorMessage: Code=0x{err.Error.Value:X8}, Reason={err.Reason ?? "(null)"}"));
                        }

                        pos += msgLen;
                    }

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

                var unexpectedExit = _running;

                _running = false;
                _dead = true;

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
            if (packetSize < 8 || packetSize > MaxPacketSize)
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
            Disconnect();
            _receiveCts?.Dispose();
            _stream?.Dispose();
            _socket?.Dispose();
            _sendLock?.Dispose();
        }
    }
}
