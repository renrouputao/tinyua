using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Transport
{
    internal class ChannelSecurityToken
    {
        internal uint ChannelId { get; set; }
        internal uint TokenId { get; set; }
        internal DateTime CreatedAt { get; set; }
        internal uint RevisedLifetime { get; set; }

        internal ChannelSecurityToken()
        {
            ChannelId = 0;
            TokenId = 0;
            CreatedAt = DateTime.MinValue;
            RevisedLifetime = 0;
        }
    }

    internal class SecureConnection
    {
        private uint _sequenceNumber;
        private uint? _peerSequenceNumber;
        private readonly List<MessageChunk> _incomingParts;
        private bool _isOpen;
        private bool _allowPrevToken;
        private int _maxChunkSize;
        private readonly object _tokenLock = new();

        internal SecurityPolicy SecurityPolicy { get; private set; }
        internal ChannelSecurityToken SecurityToken { get; }
        internal ChannelSecurityToken NextSecurityToken { get; }
        internal ChannelSecurityToken PrevSecurityToken { get; }
        internal byte[] LocalNonce { get; private set; }
        internal byte[] RemoteNonce { get; private set; }

        internal SecureConnection(SecurityPolicy securityPolicy)
        {
            SecurityPolicy = securityPolicy ?? new NoneSecurityPolicy();
            _sequenceNumber = 0;
            _peerSequenceNumber = null;
            _incomingParts = new List<MessageChunk>();
            _isOpen = false;
            _allowPrevToken = false;
            _maxChunkSize = 65536;

            SecurityToken = new ChannelSecurityToken();
            NextSecurityToken = new ChannelSecurityToken();
            PrevSecurityToken = new ChannelSecurityToken();
        }

        internal bool IsOpen => _isOpen;

        internal void SetChannel(ChannelSecurityToken token, SecurityTokenRequestType requestType, byte[] clientNonce, byte[]? serverNonce = null)
        {
            lock (_tokenLock)
            {
                if (requestType == SecurityTokenRequestType.Issue)
                {
                    SecurityToken.ChannelId = token.ChannelId;
                    SecurityToken.TokenId = token.TokenId;
                    SecurityToken.CreatedAt = token.CreatedAt;
                    SecurityToken.RevisedLifetime = token.RevisedLifetime;

                    LocalNonce = clientNonce;
                    RemoteNonce = serverNonce;

                    _isOpen = true;

                    SecurityDebugLogger.LogStage("SecureConnection.SetChannel",
                        ("requestType", "Issue"),
                        ("channelId", SecurityToken.ChannelId),
                        ("tokenId", SecurityToken.TokenId),
                        ("revisedLifetime", SecurityToken.RevisedLifetime),
                        ("clientNonceLen", clientNonce?.Length ?? -1),
                        ("serverNonceLen", serverNonce?.Length ?? -1),
                        ("policy", SecurityPolicy.Uri));

                    SecurityPolicy.MakeLocalSymmetricKey(RemoteNonce, LocalNonce);
                    SecurityPolicy.MakeRemoteSymmetricKey(LocalNonce, RemoteNonce);
                }
                else
                {
                    NextSecurityToken.ChannelId = token.ChannelId;
                    NextSecurityToken.TokenId = token.TokenId;
                    NextSecurityToken.CreatedAt = token.CreatedAt;
                    NextSecurityToken.RevisedLifetime = token.RevisedLifetime;

                    LocalNonce = clientNonce;
                    RemoteNonce = serverNonce;

                    SecurityDebugLogger.LogStage("SecureConnection.SetChannel",
                        ("requestType", "Renew"),
                        ("channelId", NextSecurityToken.ChannelId),
                        ("tokenId", NextSecurityToken.TokenId),
                        ("clientNonceLen", clientNonce?.Length ?? -1),
                        ("serverNonceLen", serverNonce?.Length ?? -1),
                        ("policy", SecurityPolicy.Uri));
                }

                _allowPrevToken = true;
            }
        }

        internal OpenSecureChannelResult Open(OpenSecureChannelParameters parameters, IServerContext server)
        {
            LocalNonce = new byte[SecurityPolicy.NonceLength];
            if (LocalNonce.Length > 0)
            {
                RandomNumberGenerator.Fill(LocalNonce);
            }
            RemoteNonce = parameters.ClientNonce;

            var response = new OpenSecureChannelResult
            {
                ServerNonce = LocalNonce
            };

            if (!_isOpen || parameters.RequestType == SecurityTokenRequestType.Issue)
            {
                _isOpen = true;
                SecurityToken.TokenId = 13;
                SecurityToken.ChannelId = server.GetNewChannelId();
                SecurityToken.RevisedLifetime = parameters.RequestedLifetime;
                SecurityToken.CreatedAt = DateTime.UtcNow;

                response.SecurityToken = SecurityToken;

                SecurityPolicy.MakeLocalSymmetricKey(RemoteNonce, LocalNonce);
                SecurityPolicy.MakeRemoteSymmetricKey(LocalNonce, RemoteNonce);
            }
            else
            {
                NextSecurityToken.ChannelId = SecurityToken.ChannelId;
                NextSecurityToken.TokenId = SecurityToken.TokenId + 1;
                NextSecurityToken.RevisedLifetime = parameters.RequestedLifetime;
                NextSecurityToken.CreatedAt = DateTime.UtcNow;

                response.SecurityToken = NextSecurityToken;
            }

            return response;
        }

        internal void Close()
        {
            _isOpen = false;
        }

        internal void RevolveTokens()
        {
            lock (_tokenLock)
            {
                PrevSecurityToken.ChannelId = SecurityToken.ChannelId;
                PrevSecurityToken.TokenId = SecurityToken.TokenId;
                PrevSecurityToken.CreatedAt = SecurityToken.CreatedAt;
                PrevSecurityToken.RevisedLifetime = SecurityToken.RevisedLifetime;

                SecurityToken.ChannelId = NextSecurityToken.ChannelId;
                SecurityToken.TokenId = NextSecurityToken.TokenId;
                SecurityToken.CreatedAt = NextSecurityToken.CreatedAt;
                SecurityToken.RevisedLifetime = NextSecurityToken.RevisedLifetime;

                NextSecurityToken.ChannelId = 0;
                NextSecurityToken.TokenId = 0;
                NextSecurityToken.CreatedAt = DateTime.MinValue;
                NextSecurityToken.RevisedLifetime = 0;
            }

            SecurityPolicy.MakeLocalSymmetricKey(RemoteNonce, LocalNonce);
        }

        internal byte[] MessageToBinary(byte[] message, byte[]? messageType = null, uint requestId = 0)
            => MessageToBinaryCore(new ArraySegment<byte>(message), messageType ?? MessageType.SecureMessage, requestId);

        private byte[] MessageToBinaryCore(ArraySegment<byte> message, byte[] messageType, uint requestId)
        {
            uint channelId = SecurityToken.ChannelId;
            uint tokenId = SecurityToken.TokenId;

            if (MessageType.Equals(messageType, MessageType.SecureOpen))
            {
                if (!_isOpen)
                {
                    channelId = 0;
                }
                tokenId = 0;
            }

            var chunks = MessageChunk.MessageToChunks(
                SecurityPolicy,
                message,
                _maxChunkSize,
                messageType,
                channelId,
                requestId,
                tokenId);

            foreach (var chunk in chunks)
            {
                chunk.SequenceHeader.SequenceNumber = NextSequenceNumber();
            }

            if (chunks.Count == 1)
                return chunks[0].ToBinary();

            var buffers = new byte[chunks.Count][];
            var total = 0;
            for (int i = 0; i < chunks.Count; i++)
            {
                buffers[i] = chunks[i].ToBinary();
                total += buffers[i].Length;
            }

            var result = new byte[total];
            var offset = 0;
            foreach (var buffer in buffers)
            {
                Buffer.BlockCopy(buffer, 0, result, offset, buffer.Length);
                offset += buffer.Length;
            }

            return result;
        }

        private uint NextSequenceNumber()
        {
            // OPC UA Part 6: the sender must roll over to a value below 1024 before exceeding
            // 4294966271 (0xFFFFFBFF). Receivers accept a single wrap from >(max-1024) to <1024.
            const uint maxSequenceNumber = 4294966271;
            _sequenceNumber++;
            if (_sequenceNumber > maxSequenceNumber)
                _sequenceNumber = 1;
            return _sequenceNumber;
        }

        internal byte[] MessageToBinary(ArraySegment<byte> body, byte[]? messageType = null, uint requestId = 0)
        {
            messageType ??= MessageType.SecureMessage;

            if (MessageType.Equals(messageType, MessageType.SecureOpen))
                return MessageToBinaryCore(body, messageType, requestId);

            var crypto = SecurityPolicy.SymmetricCryptography;

            if (crypto.SignatureSize == 0 && crypto.PlainBlockSize <= 1)
            {
                int maxBodySize = MessageChunk.MaxBodySize(crypto, _maxChunkSize);
                if (body.Count <= maxBodySize)
                {
                    var sequenceNumber = NextSequenceNumber();

                    int totalSize = 24 + body.Count;
                    var result = new byte[totalSize];

                    var mt = messageType;
                    result[0] = mt[0];
                    result[1] = mt[1];
                    result[2] = mt[2];
                    result[3] = ChunkType.Single;
                    int bodySize = 12 + body.Count;
                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)(bodySize + 12));
                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), SecurityToken.ChannelId);

                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), SecurityToken.TokenId);

                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), sequenceNumber);
                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20), requestId);

                    if (body.Count > 0)
                        Buffer.BlockCopy(body.Array!, body.Offset, result, 24, body.Count);

                    return result;
                }
            }

            return MessageToBinaryCore(body, messageType, requestId);
        }

        internal object ReceiveFromHeaderAndBody(Header header, byte[] body)
        {

            if (header.IsSecureMessage || header.IsSecureClose)
            {
                var decoder = new BinaryDecoder(body);
                var securityHeader = SymmetricAlgorithmHeader.Decode(decoder);
                CheckSymmetricHeader(securityHeader);

                var chunk = new MessageChunk(SecurityPolicy.SymmetricCryptography)
                {
                    MessageHeader = header,
                    SecurityHeader = securityHeader
                };
                MessageChunk.DecryptInto(chunk, decoder);
                return Receive(chunk);
            }

            if (header.IsSecureOpen)
            {
                var chunk = MessageChunk.FromHeaderAndBody(SecurityPolicy, header, new BinaryDecoder(body));
                return Receive(chunk);
            }

            if (header.IsHello)
            {
                var hello = Hello.Decode(new BinaryDecoder(body));
                _maxChunkSize = (int)hello.ReceiveBufferSize;
                return hello;
            }

            if (header.IsAcknowledge)
            {
                var ack = Acknowledge.Decode(new BinaryDecoder(body));
                _maxChunkSize = (int)ack.SendBufferSize;
                return ack;
            }

            if (header.IsError)
            {
                var error = ErrorMessage.Decode(new BinaryDecoder(body));
                return error;
            }

            throw new UaException(0x80000000, $"Unsupported message type: {MessageType.ToString(header.MessageType)}");
        }

        private void CheckSymmetricHeader(SymmetricAlgorithmHeader header)
        {
            if (header.TokenId != SecurityToken.TokenId)
            {
                if (header.TokenId != NextSecurityToken.TokenId)
                {
                    if (_allowPrevToken && header.TokenId == PrevSecurityToken.TokenId)
                    {
                        var timeout = PrevSecurityToken.CreatedAt.AddMilliseconds(PrevSecurityToken.RevisedLifetime * 1.25);
                        if (timeout < DateTime.UtcNow)
                        {
                            throw new UaException(0x80000000, $"Security token {header.TokenId} has timed out");
                        }
                        return;
                    }
                    throw new UaException(0x80000000, $"Invalid security token id: {header.TokenId}");
                }

                RevolveTokens();
                RetirePreviousToken();
            }

            if (PrevSecurityToken.TokenId != 0)
            {
                RetirePreviousToken();
            }
        }

        /// <summary>
        /// Re-derives the remote symmetric key for the now-current token and clears the previous
        /// token slot. Called once the first message on a rotated token is seen (whether the
        /// rotation was driven by an incoming header or by a local send that revolved the tokens).
        /// </summary>
        private void RetirePreviousToken()
        {
            SecurityPolicy.MakeRemoteSymmetricKey(LocalNonce, RemoteNonce);
            PrevSecurityToken.ChannelId = 0;
            PrevSecurityToken.TokenId = 0;
            PrevSecurityToken.CreatedAt = DateTime.MinValue;
            PrevSecurityToken.RevisedLifetime = 0;
        }

        private object Receive(MessageChunk chunk)
        {
            CheckIncomingChunk(chunk);
            _incomingParts.Add(chunk);

            if (chunk.MessageHeader.ChunkType == ChunkType.Intermediate)
            {
                return null;
            }

            if (chunk.MessageHeader.ChunkType == ChunkType.Abort)
            {
                var error = ErrorMessage.Decode(new BinaryDecoder(chunk.Body));
                _incomingParts.Clear();
                return null;
            }

            if (chunk.MessageHeader.ChunkType == ChunkType.Single)
            {
                var message = new Message(new List<MessageChunk>(_incomingParts));
                _incomingParts.Clear();
                return message;
            }

            throw new UaException(0x80000000, $"Unsupported chunk type: {(char)chunk.MessageHeader.ChunkType}");
        }

        private void CheckIncomingChunk(MessageChunk chunk)
        {
            if (!chunk.MessageHeader.IsSecureOpen)
            {
                if (chunk.MessageHeader.ChannelId != SecurityToken.ChannelId)
                {
                    throw new UaException(0x80000000, $"Wrong channel id: {chunk.MessageHeader.ChannelId}");
                }
            }

            if (_incomingParts.Count > 0)
            {
                if (_incomingParts[0].SequenceHeader.RequestId != chunk.SequenceHeader.RequestId)
                {
                    throw new UaException(0x80000000, $"Wrong request id: {chunk.SequenceHeader.RequestId}");
                }
            }

            var seqNum = chunk.SequenceHeader.SequenceNumber;
            if (!chunk.MessageHeader.IsSecureOpen && _peerSequenceNumber.HasValue)
            {
                // A valid peer sequence number must be strictly greater than the last one,
                // except for a single permitted rollover near uint.MaxValue (OPC UA Part 6).
                const uint minSequenceNumber = uint.MaxValue - 1024;
                const uint maxRolloverSequenceNumber = 1024;

                bool isIncreasing = seqNum > _peerSequenceNumber.Value;
                bool isWrap = _peerSequenceNumber.Value > minSequenceNumber
                    && seqNum < maxRolloverSequenceNumber;

                if (!isIncreasing && !isWrap)
                {
                    throw new UaException(0x80880000,
                        $"Out-of-order sequence number: got {seqNum}, expected > {_peerSequenceNumber.Value}");
                }
            }
            _peerSequenceNumber = seqNum;
        }

    }

    internal enum SecurityTokenRequestType
    {
        Issue = 0,
        Renew = 1
    }

    /// <summary>
    /// Parameters for an OpenSecureChannel service request.
    /// </summary>
    public class OpenSecureChannelParameters
    {
        /// <summary>Gets or sets whether to issue a new token or renew an existing one.</summary>
        internal SecurityTokenRequestType RequestType { get; set; }

        /// <summary>Gets or sets the requested message security mode.</summary>
        internal MessageSecurityMode SecurityMode { get; set; }

        /// <summary>Gets or sets the client-generated nonce for key derivation.</summary>
        internal byte[] ClientNonce { get; set; }

        /// <summary>Gets or sets the requested lifetime of the security token in milliseconds.</summary>
        internal uint RequestedLifetime { get; set; }
    }

    /// <summary>
    /// Result returned by an OpenSecureChannel service operation.
    /// </summary>
    public class OpenSecureChannelResult
    {
        /// <summary>Gets or sets the server protocol version.</summary>
        internal uint ServerProtocolVersion { get; set; }

        /// <summary>Gets or sets the issued or renewed channel security token.</summary>
        internal ChannelSecurityToken SecurityToken { get; set; } = new ChannelSecurityToken();

        /// <summary>Gets or sets the server-generated nonce used for key derivation.</summary>
        internal byte[]? ServerNonce { get; set; }
    }

    internal interface IServerContext
    {
        uint GetNewChannelId();
    }
}
