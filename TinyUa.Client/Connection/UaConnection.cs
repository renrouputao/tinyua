using TinyUa.Core;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Core.Binary;
using TinyUa.Core.Security;
using TinyUa.Core.Security.Certificates;
using TinyUa.Transport;
using TinyUa.Core.Types;
using TinyUa.Client.Services;

namespace TinyUa.Client.Connection
{

    internal class UaConnection : IDisposable
    {
        private readonly int _timeout;
        private readonly ILogger _logger;
        private UaSocketClient? _socket;
        private SecurityPolicy _securityPolicy;
        private NodeId? _sessionId;
        private NodeId? _authenticationToken;
        private uint _requestHandle;

        private byte[]? _serverCertificate;
        private byte[]? _serverNonce;

        internal NodeId? SessionId => _sessionId;
        internal NodeId? AuthenticationToken => _authenticationToken;
        internal string? UserTokenPolicyId { get; set; }
        internal uint RevisedChannelLifetime => _socket?.RevisedChannelLifetime ?? 3600000;

            internal bool IsAlive => _socket?.IsAlive ?? false;

        /// <summary>Milliseconds since the last request was sent, or <see cref="long.MaxValue"/> when not connected.</summary>
        internal long IdleMilliseconds => _socket?.IdleMilliseconds ?? long.MaxValue;

        internal event Action<Exception?>? ConnectionLost;

        internal UaConnection(int timeout = 1000, ILogger? logger = null)
        {
            _timeout = timeout;
            _securityPolicy = new NoneSecurityPolicy();
            _logger = logger ?? NullLogger.Instance;
        }

        internal void SetDebugMode(bool enabled)
        {
            if (_socket != null) _socket.DebugMode = enabled;
        }

        internal void SetSecurityPolicy(SecurityPolicy policy)
        {
            _securityPolicy = policy ?? new NoneSecurityPolicy();
            if (_socket != null)
            {
                _logger.LogDebug($"SecurityPolicy changed to {_securityPolicy.Uri} (existing socket will be recreated on next ConnectAsync)");
            }
        }

        internal SecurityPolicy SecurityPolicy => _securityPolicy;

        internal async Task ConnectAsync(string host, int port)
        {
            if (_socket != null)
            {
                _socket.ConnectionLost -= OnSocketConnectionLost;
                _socket.Dispose();
            }
            _socket = new UaSocketClient(_timeout, _securityPolicy, _logger);
            _socket.ConnectionLost += OnSocketConnectionLost;
            await _socket.ConnectAsync(host, port).ConfigureAwait(false);
        }

        private void OnSocketConnectionLost(Exception? ex)
        {
            ConnectionLost?.Invoke(ex);
        }

        internal void Disconnect() => _socket?.Disconnect();

        internal async Task DisconnectAsync()
        {
            if (_socket != null) await _socket.DisconnectAsync().ConfigureAwait(false);
        }

        internal async Task<Acknowledge> SendHelloAsync(string endpointUrl, uint maxMessageSize = 0)
            => await _socket!.SendHelloAsync(endpointUrl, maxMessageSize).ConfigureAwait(false);

        /// <summary>
        /// Builds a request header with the session token, a monotonically increasing request
        /// handle, and the given timeout hint. All service calls go through this single factory.
        /// </summary>
        internal RequestHeader CreateRequestHeader(uint timeoutHint)
        {
            return new RequestHeader
            {
                AuthenticationToken = _authenticationToken ?? new NodeId(),
                Timestamp = DateTime.UtcNow,
                RequestHandle = Interlocked.Increment(ref _requestHandle),
                TimeoutHint = timeoutHint
            };
        }

        /// <summary>
        /// Sends a service request with a uniformly populated header, decodes the response, and
        /// checks the service result. The one entry point for all session-level services.
        /// </summary>
        internal async Task<TResponse> InvokeAsync<TRequest, TResponse>(TRequest request)
            where TRequest : IServiceRequest
            where TResponse : IDecodable<TResponse>, IServiceResponse
        {
            request.RequestHeader = CreateRequestHeader((uint)Math.Max(_timeout, 0));
            var body = await _socket!.SendRequestAsync(request).ConfigureAwait(false);
            var decoder = new BinaryDecoder(body);
            var response = TResponse.Decode(decoder);
            response.ResponseHeader.ServiceResult.Check();
            return response;
        }

        internal async Task<EndpointDescription[]?> GetEndpointsAsync(string endpointUrl)
        {
            var request = new GetEndpointsRequest
            {
                EndpointUrl = endpointUrl,
                LocaleIds = null,
                ProfileUris = null
            };
            var response = await InvokeAsync<GetEndpointsRequest, GetEndpointsResponse>(request).ConfigureAwait(false);
            return response.Endpoints;
        }

        internal async Task<OpenSecureChannelResult> OpenSecureChannelAsync(OpenSecureChannelParameters parameters)
            => await _socket!.OpenSecureChannelAsync(parameters).ConfigureAwait(false);

        internal async Task<OpenSecureChannelResult> RenewSecureChannelAsync(uint requestedLifetime = 3600000)
        {
            var nonce = new byte[_securityPolicy.NonceLength];
            if (nonce.Length > 0)
                RandomNumberGenerator.Fill(nonce);

            var parameters = new OpenSecureChannelParameters
            {
                RequestType = SecurityTokenRequestType.Renew,
                SecurityMode = _securityPolicy.SecurityMode,
                ClientNonce = nonce.Length > 0 ? nonce : null,
                RequestedLifetime = requestedLifetime
            };
            return await OpenSecureChannelAsync(parameters).ConfigureAwait(false);
        }

        internal async Task CloseSecureChannelAsync()
        {
            if (_socket == null) return;
            try { await _socket.SendRequestNoWait(new CloseSecureChannelRequest(), null, MessageType.SecureClose).ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogDebug(ex, "CloseSecureChannel error (ignored)"); }
        }

        internal async Task CloseSessionAsync()
        {
            if (_sessionId == null || _authenticationToken == null) return;
            try
            {
                var request = new CloseSessionRequest { DeleteSubscriptions = true };
                await InvokeAsync<CloseSessionRequest, CloseSessionResponse>(request).ConfigureAwait(false);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "CloseSession error (ignored)"); }
            finally { _sessionId = null; _authenticationToken = null; }
        }

        internal async Task<CreateSessionResponse> CreateSessionAsync(string endpointUrl, string sessionName = "OpcUa Session",
            string? applicationUri = null, string? productUri = null, uint requestedSessionTimeout = 3600000)
        {
            var clientNonce = new byte[_securityPolicy.NonceLength > 0 ? _securityPolicy.NonceLength : 32];
            if (clientNonce.Length > 0)
                RandomNumberGenerator.Fill(clientNonce);

            var request = new CreateSessionRequest
            {
                Parameters = new CreateSessionParameters
                {
                    ClientDescription = new ApplicationDescription
                    {
                        ApplicationUri = applicationUri ?? "urn:openua:client",
                        ProductUri = productUri ?? "urn:openua",
                        ApplicationName = new LocalizedText(sessionName),
                        ApplicationType = ApplicationType.Client
                    },
                    EndpointUrl = endpointUrl,
                    SessionName = sessionName,
                    ClientNonce = clientNonce,
                    ClientCertificate = _securityPolicy.SenderCertificate,
                    RequestedSessionTimeout = requestedSessionTimeout
                }
            };
            var response = await InvokeAsync<CreateSessionRequest, CreateSessionResponse>(request).ConfigureAwait(false);

            // Verify the server's signature before trusting the response. Per OPC UA Part 4 §5.6.2,
            // the server signs clientCertificate || clientNonce with its private key, proving it
            // holds the key for the certificate it presented. Without this check, an attacker who
            // can inject a CreateSessionResponse (e.g. via a hijacked channel) could feed the
            // client a fake server nonce/certificate. The OPN verify already proves key ownership
            // at channel-open time; this re-proves it at session-creation time over the client's
            // nonce, binding the session to the authenticated channel.
            VerifyServerSignature(response.ServerSignature, _securityPolicy.SenderCertificate, clientNonce);

            _sessionId = response.SessionId;
            _authenticationToken = response.AuthenticationToken;

            _serverCertificate = response.ServerCertificate;
            _serverNonce = response.ServerNonce;

            return response;
        }

        internal async Task ActivateSessionAsync(UserIdentityToken? userIdentity = null)
        {
            var parameters = new ActivateSessionParameters { UserIdentity = userIdentity };
            ComputeClientSignature(parameters);

            var request = new ActivateSessionRequest { Parameters = parameters };
            await InvokeAsync<ActivateSessionRequest, ActivateSessionResponse>(request).ConfigureAwait(false);
        }

        internal async Task ActivateSessionAsync(NodeId sessionId, NodeId authenticationToken, UserIdentityToken? userIdentity = null)
        {
            _authenticationToken = authenticationToken;
            _sessionId = sessionId;
            var parameters = new ActivateSessionParameters { UserIdentity = userIdentity };
            ComputeClientSignature(parameters);

            var request = new ActivateSessionRequest { Parameters = parameters };
            await InvokeAsync<ActivateSessionRequest, ActivateSessionResponse>(request).ConfigureAwait(false);
        }

        private void ComputeClientSignature(ActivateSessionParameters parameters)
        {
            var asymCrypto = _securityPolicy.AsymmetricCryptography;
            if (asymCrypto.SignatureSize == 0)
                return;

            if (_serverCertificate == null || _serverCertificate.Length == 0
                || _serverNonce == null || _serverNonce.Length == 0)
                return;

            var signedData = new byte[_serverCertificate.Length + _serverNonce.Length];
            Buffer.BlockCopy(_serverCertificate, 0, signedData, 0, _serverCertificate.Length);
            Buffer.BlockCopy(_serverNonce, 0, signedData, _serverCertificate.Length, _serverNonce.Length);

            var signature = asymCrypto.Sign(signedData);
            parameters.ClientSignature.Algorithm = GetAsymmetricSignatureUri();
            parameters.ClientSignature.Signature = signature;
        }

        private string GetAsymmetricSignatureUri()
        {
            var uri = _securityPolicy.Uri;
            if (uri.EndsWith("#Aes256_Sha256_RsaPss"))
                return "http://opcfoundation.org/UA/security/rsa-pss-sha2-256";
            return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        }

        /// <summary>
        /// Verifies the ServerSignature returned in CreateSessionResponse. Per OPC UA Part 4
        /// §5.6.2, the signed data is clientCertificate || clientNonce. A secure policy that
        /// receives no signature, or a signature that does not validate, is treated as a
        /// channel-compromise (possible MITM) and rejected. None policy skips verification.
        /// </summary>
        private void VerifyServerSignature(SignatureData? serverSignature, byte[]? clientCertificate, byte[] clientNonce)
        {
            var asymCrypto = _securityPolicy.AsymmetricCryptography;
            if (asymCrypto.RemoteSignatureSize == 0)
                return; // None policy — server does not sign

            var signature = serverSignature?.Signature;
            if (signature == null || signature.Length == 0)
                throw new CryptographicException(
                    "Server signature is missing in CreateSession response — the server must sign clientCertificate||clientNonce for secure policies");

            // Build the signed data: clientCertificate || clientNonce (same order as the server
            // signs per spec; mirrors ComputeClientSignature which signs serverCertificate||serverNonce).
            var clientCert = clientCertificate ?? Array.Empty<byte>();
            var signedData = new byte[clientCert.Length + clientNonce.Length];
            Buffer.BlockCopy(clientCert, 0, signedData, 0, clientCert.Length);
            if (clientNonce.Length > 0)
                Buffer.BlockCopy(clientNonce, 0, signedData, clientCert.Length, clientNonce.Length);

            if (!asymCrypto.VerifyData(signedData, signature))
                throw new CryptographicException(
                    "Server signature verification failed — the server may not hold the private key for its certificate (possible MITM)");
        }

        internal async Task<NotificationMessage> RepublishAsync(uint subscriptionId, uint sequenceNumber)
        {
            var request = new RepublishRequest
            {
                Parameters = new RepublishParameters { SubscriptionId = subscriptionId, RetransmitSequenceNumber = sequenceNumber }
            };
            var response = await InvokeAsync<RepublishRequest, RepublishResponse>(request).ConfigureAwait(false);
            return response.NotificationMessage;
        }

        internal async Task<BrowseResult[]?> BrowseAsync(NodeId nodeId, BrowseDirection direction = BrowseDirection.Forward, uint maxReferences = 100)
        {
            var request = new BrowseRequest
            {
                Parameters = new BrowseParameters
                {
                    RequestedMaxReferencesPerNode = maxReferences,
                    NodesToBrowse = new[] { new BrowseDescription
                    {
                        NodeId = nodeId, BrowseDirection = direction, ReferenceTypeId = new NodeId(33, 0),
                        IncludeSubtypes = true, NodeClassMask = 0, ResultMask = 63
                    }}
                }
            };
            var response = await InvokeAsync<BrowseRequest, BrowseResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        internal async Task<BrowseResult[]?> BrowseNextAsync(byte[] continuationPoint)
        {
            var request = new BrowseNextRequest
            {
                ReleaseContinuationPoints = false,
                ContinuationPoints = new[] { continuationPoint }
            };
            var response = await InvokeAsync<BrowseNextRequest, BrowseNextResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        internal async Task<DataValue[]?> ReadAsync(NodeId nodeId, AttributeId attributeId = AttributeId.Value)
        {
            var request = new ReadRequest
            {
                Parameters = new ReadParameters
                {
                    MaxAge = 0, TimestampsToReturn = TimestampsToReturn.Both,
                    NodesToRead = new[] { new ReadValueId { NodeId = nodeId, AttributeId = attributeId } }
                }
            };
            var response = await InvokeAsync<ReadRequest, ReadResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        internal async Task<ReadResult[]?> ReadAsync(NodeId[] nodeIds, AttributeId attributeId = AttributeId.Value)
        {
            var nodesToRead = new ReadValueId[nodeIds.Length];
            for (int i = 0; i < nodeIds.Length; i++)
                nodesToRead[i] = new ReadValueId { NodeId = nodeIds[i], AttributeId = attributeId };

            var request = new ReadRequest
            {
                Parameters = new ReadParameters { MaxAge = 0, TimestampsToReturn = TimestampsToReturn.Both, NodesToRead = nodesToRead }
            };
            var response = await InvokeAsync<ReadRequest, ReadResponse>(request).ConfigureAwait(false);

            var results = new ReadResult[nodeIds.Length];
            for (int i = 0; i < nodeIds.Length; i++)
            {
                var dv = response.Results?[i];
                results[i] = new ReadResult
                {
                    NodeId = nodeIds[i],
                    StatusCode = dv?.StatusCode ?? StatusCode.Bad,
                    DataValue = dv,
                };
            }
            return results;
        }

        internal async Task<StatusCode?> WriteAsync(NodeId nodeId, DataValue value)
        {
            var results = await WriteAsync(new[] { new WriteValue { NodeId = nodeId, Value = value } }).ConfigureAwait(false);
            return results != null && results.Length > 0 ? results[0].StatusCode : null;
        }

        internal async Task<StatusCode?> WriteAsync(NodeId nodeId, object value, VariantType? variantType = null)
            => await WriteAsync(nodeId, new DataValue(new Variant(value, variantType))).ConfigureAwait(false);

        internal async Task<WriteResult[]?> WriteAsync(WriteValue[] nodesToWrite)
        {
            var request = new WriteRequest
            {
                Parameters = new WriteParameters { NodesToWrite = nodesToWrite }
            };
            var response = await InvokeAsync<WriteRequest, WriteResponse>(request).ConfigureAwait(false);

            var results = new WriteResult[nodesToWrite.Length];
            for (int i = 0; i < nodesToWrite.Length; i++)
                results[i] = new WriteResult { NodeId = nodesToWrite[i].NodeId, StatusCode = response.Results?[i] ?? StatusCode.Bad };
            return results;
        }

        internal async Task<TResponse> SendRequestAsync<TRequest, TResponse>(TRequest request, byte[]? messageType = null)
            where TRequest : IEncodable where TResponse : IDecodable<TResponse>, new()
        {
            var body = await _socket!.SendRequestAsync(request, messageType).ConfigureAwait(false);
            var decoder = new BinaryDecoder(body);
            return TResponse.Decode(decoder);
        }

        internal Task SendRequestNoWaitAsync<T>(T request, Action<byte[]>? callback = null, Action<Exception>? onError = null, TimeSpan? responseTimeout = null) where T : IEncodable
            => _socket!.SendRequestNoWait(request, callback, null, onError, responseTimeout);

        internal byte[] PrepareEncodedReadRequest(NodeId[] nodeIds, AttributeId attributeId = AttributeId.Value)
        {
            var nodesToRead = new ReadValueId[nodeIds.Length];
            for (int i = 0; i < nodeIds.Length; i++)
                nodesToRead[i] = new ReadValueId { NodeId = nodeIds[i], AttributeId = attributeId };
            var request = new ReadRequest
            {
                RequestHeader = CreateRequestHeader((uint)Math.Max(_timeout, 0)),
                Parameters = new ReadParameters { MaxAge = 0, TimestampsToReturn = TimestampsToReturn.Both, NodesToRead = nodesToRead }
            };
            var enc = new BinaryEncoder(4096);
            request.Encode(enc);
            return enc.ToByteArray();
        }

        internal async Task<DataValue[]> ReadWithEncodedBodyAsync(byte[] encodedBody)
        {
            var body = await _socket!.SendEncodedBodyAsync(encodedBody).ConfigureAwait(false);
            var decoder = new BinaryDecoder(body);
            var response = ReadResponse.Decode(decoder);
            response.ResponseHeader.ServiceResult.Check();
            return response.Results!;
        }

        public void Dispose()
        {
            Disconnect();
            _socket?.Dispose();
        }
    }
}
