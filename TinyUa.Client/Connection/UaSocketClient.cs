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

        private readonly byte[] _headerBuffer = new byte[8];
        private readonly byte[] _channelIdBuffer = new byte[4];

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

            var encoder = new BinaryEncoder();
            var header = new Header(MessageType.Hello, ChunkType.Single);
            hello.Encode(encoder);
            header.BodySize = encoder.Length;

            var headerEncoder = new BinaryEncoder();
            header.Encode(headerEncoder);

            _logger.LogDebug($"Sending Hello: {headerEncoder.Length + encoder.Length} bytes");

            var combinedBuffer = new byte[headerEncoder.Length + encoder.Length];
            Buffer.BlockCopy(headerEncoder.ToByteArray(), 0, combinedBuffer, 0, headerEncoder.Length);
            Buffer.BlockCopy(encoder.ToByteArray(), 0, combinedBuffer, headerEncoder.Length, encoder.Length);

            if (_stream == null)
                throw new InvalidOperationException("Socket is not connected");

            await _stream!.WriteAsync(combinedBuffer, 0, combinedBuffer.Length).WithTimeout(_timeout, "Hello write operation timed out");

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
            var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

            byte[] message;
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

                message = _connection.MessageToBinary(bodySegment, messageType, (uint)requestId);

                if (debugEnabled)
                    _logger.LogDebug($"Sending request {requestId}: {message.Length} bytes");

                if (_dead)
                    throw new SocketException((int)SocketError.ConnectionReset);

                _callbacks[requestId] = tcs;

                await _stream!.WriteAsync(message, 0, message.Length, cancellationToken).ConfigureAwait(false);
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
        internal async Task SendRequestNoWait<T>(T request, Action<byte[]>? callback = null, byte[]? messageType = null, Action<Exception>? onError = null) where T : IEncodable
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

                var message = _connection.MessageToBinary(bodySegment, messageType, (uint)requestId);

                if (_dead)
                    throw new SocketException((int)SocketError.ConnectionReset);
                _callbacks[requestId] = tcs;

                await _stream!.WriteAsync(message, 0, message.Length).ConfigureAwait(false);
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
                InvokeCallbackAsync(tcs.Task, callback, onError).Forget(_logger, nameof(InvokeCallbackAsync));
            }
        }

        private async Task InvokeCallbackAsync(Task<byte[]> task, Action<byte[]>? callback, Action<Exception>? onError)
        {
            byte[] result;
            try
            {
                result = await task.ConfigureAwait(false);
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
                callback?.Invoke(result);
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

            byte[] message;
            if (!await _sendLock.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false))
                throw new TimeoutException("Timed out waiting for send lock");
            try
            {
                if (!MessageType.Equals(messageType, MessageType.SecureOpen))
                {
                    if (_connection.NextSecurityToken.TokenId != 0)
                        _connection.RevolveTokens();
                }
                if (_dead)
                    throw new SocketException((int)SocketError.ConnectionReset);
                _callbacks[requestId] = tcs;

                message = _connection.MessageToBinary(encodedBody, messageType, (uint)requestId);
                await _stream!.WriteAsync(message, 0, message.Length).ConfigureAwait(false);
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
            _logger.LogDebug("Receive loop started (async)");
            Exception? exitException = null;

            try
            {
                var debugEnabled = _logger.IsEnabled(LogLevel.Debug);
                while (_running && !ct.IsCancellationRequested)
                {
                    var header = await ReadHeaderAsync(ct);
                    if (header == null)
                    {
                        _logger.LogWarning("Receive loop: stream closed by remote (FIN received)");
                        break;
                    }

                    if (debugEnabled)
                        _logger.LogDebug($"Received header: {header}");

                    const int MaxBodySize = 16 * 1024 * 1024;
                    if (header.BodySize < 0 || header.BodySize > MaxBodySize)
                    {
                        _logger.LogError($"Invalid BodySize: {header.BodySize}, closing connection");
                        break;
                    }

                    var body = new byte[header.BodySize];
                    var read = 0;
                    while (read < body.Length)
                    {
                        var bytesRead = await _stream!.ReadAsync(body, read, body.Length - read, ct);
                        if (bytesRead == 0) break;
                        read += bytesRead;
                    }
                    if (read < body.Length)
                    {
                        _logger.LogWarning($"Incomplete body read: {read}/{body.Length}, closing connection");
                        break;
                    }

                    if (debugEnabled)
                        _logger.LogDebug($"Received body: {body.Length} bytes");

                    object? message;
                    try
                    {
                        message = _connection.ReceiveFromHeaderAndBody(header, body);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"Receive loop: message parsing failed (header={header}), attempting to fault callback and continue");

                        if (header.IsSecureMessage && body.Length >= 12)
                        {
                            try
                            {
                                var reqId = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8));
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

                            foreach (var callback in _callbacks.Values)
                                callback.TrySetException(ex);
                        }
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
                        else
                        {
                            if (debugEnabled)
                            {
                                _logger.LogDebug($"No callback found for request {msg.RequestId}");
                            }
                        }
                    }
                    else if (message is ErrorMessage err)
                    {
                        _logger.LogWarning($"Error message received: StatusCode=0x{err.Error.Value:X8}, Reason={err.Reason}");

                        foreach (var callback in _callbacks.Values)
                        {
                            callback.TrySetException(new UaException(err.Error.Value,
                                $"Server ErrorMessage: Code=0x{err.Error.Value:X8}, Reason={err.Reason ?? "(null)"}"));
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Receive loop cancelled");
            }
            catch (Exception ex)
            {
                exitException = ex;
                _logger.LogWarning(ex, "Receive loop exiting due to exception — socket is now dead");

            }
            finally
            {

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

        private async Task<Header?> ReadHeaderAsync(CancellationToken ct)
        {
            if (_stream == null) return null;

            var read = 0;
            while (read < 8)
            {
                var bytesRead = await _stream!.ReadAsync(_headerBuffer, read, 8 - read, ct);
                if (bytesRead == 0) return null;
                read += bytesRead;
            }

            var decoder = new BinaryDecoder(_headerBuffer);
            var header = Header.Decode(decoder);

            if (header.IsSecureMessage || header.IsSecureOpen || header.IsSecureClose)
            {
                read = 0;
                while (read < 4)
                {
                    var bytesRead = await _stream!.ReadAsync(_channelIdBuffer, read, 4 - read, ct);
                    if (bytesRead == 0) return null;
                    read += bytesRead;
                }
                header.ChannelId = BinaryPrimitives.ReadUInt32LittleEndian(_channelIdBuffer);
            }

            return header;
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
