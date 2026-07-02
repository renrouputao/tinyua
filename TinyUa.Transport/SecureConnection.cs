using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Core.Transport
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
        {
            messageType ??= MessageType.SecureMessage;

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
                _sequenceNumber++;
                if (_sequenceNumber >= uint.MaxValue)
                {
                    _sequenceNumber = 1;
                }
                chunk.SequenceHeader.SequenceNumber = _sequenceNumber;
            }

            if (chunks.Count == 1)
                return chunks[0].ToBinary();

            var result = new List<byte>();
            foreach (var chunk in chunks)
            {
                result.AddRange(chunk.ToBinary());
            }

            return result.ToArray();
        }

        internal byte[] MessageToBinary(ArraySegment<byte> body, byte[]? messageType = null, uint requestId = 0)
        {
            messageType ??= MessageType.SecureMessage;

            if (MessageType.Equals(messageType, MessageType.SecureOpen))
                return MessageToBinary(body.ToArray(), messageType, requestId);

            var crypto = SecurityPolicy.SymmetricCryptography;

            if (crypto.SignatureSize == 0 && crypto.PlainBlockSize <= 1)
            {
                int maxBodySize = MessageChunk.MaxBodySize(crypto, _maxChunkSize);
                if (body.Count <= maxBodySize)
                {
                    _sequenceNumber++;
                    if (_sequenceNumber >= uint.MaxValue)
                        _sequenceNumber = 1;

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

                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), _sequenceNumber);
                    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20), requestId);

                    if (body.Count > 0)
                        Buffer.BlockCopy(body.Array!, body.Offset, result, 24, body.Count);

                    return result;
                }
            }

            return MessageToBinary(body.ToArray(), messageType, requestId);
        }

        internal object ReceiveFromHeaderAndBody(Header header, byte[] body)
        {

            if (header.IsSecureMessage || header.IsSecureClose)
            {
                var decoder = new BinaryDecoder(body);
                var securityHeader = SymmetricAlgorithmHeader.Decode(decoder);
                CheckSymmetricHeader(securityHeader);

                var crypto = SecurityPolicy.SymmetricCryptography;
                var chunk = new MessageChunk(crypto)
                {
                    MessageHeader = header,
                    SecurityHeader = securityHeader
                };

                if (decoder.Remaining > 0)
                {
                    if (crypto.SignatureSize == 0 && crypto.PlainBlockSize <= 1)
                    {

                        chunk.SequenceHeader = SequenceHeader.Decode(decoder);
                        chunk.Body = decoder.GetRemainingBytes();
                    }
                    else
                    {
                        var encryptedData = decoder.ReadBytes(decoder.Remaining);
                        if (crypto.RemoteSignatureSize > 0 && encryptedData.Length >= crypto.RemoteSignatureSize)
                        {
                            var decrypted = crypto.Decrypt(encryptedData);

                            int sigLen = crypto.RemoteSignatureSize;
                            var signature = decrypted[^sigLen..];
                            var plaintext = decrypted[..^sigLen];

                            var headerBytes = MessageChunk.EncodeHeaderToBytes(header);
                            var securityBytes = MessageChunk.EncodeSecurityHeaderToBytes(securityHeader);
                            var signedData = new byte[headerBytes.Length + securityBytes.Length + plaintext.Length];
                            Buffer.BlockCopy(headerBytes, 0, signedData, 0, headerBytes.Length);
                            Buffer.BlockCopy(securityBytes, 0, signedData, headerBytes.Length, securityBytes.Length);
                            Buffer.BlockCopy(plaintext, 0, signedData, headerBytes.Length + securityBytes.Length, plaintext.Length);

                            crypto.Verify(signedData, signature);

                            var unpadded = crypto.RemovePadding(plaintext);
                            var bodyDecoder = new BinaryDecoder(unpadded);
                            chunk.SequenceHeader = SequenceHeader.Decode(bodyDecoder);
                            chunk.Body = bodyDecoder.GetRemainingBytes();
                        }
                        else
                        {
                            var bodyDecoder = new BinaryDecoder(encryptedData);
                            chunk.SequenceHeader = SequenceHeader.Decode(bodyDecoder);
                            chunk.Body = bodyDecoder.GetRemainingBytes();
                        }
                    }
                }

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
                SecurityPolicy.MakeRemoteSymmetricKey(LocalNonce, RemoteNonce);
                PrevSecurityToken.ChannelId = 0;
                PrevSecurityToken.TokenId = 0;
                PrevSecurityToken.CreatedAt = DateTime.MinValue;
                PrevSecurityToken.RevisedLifetime = 0;
            }

            if (PrevSecurityToken.TokenId != 0)
            {
                SecurityPolicy.MakeRemoteSymmetricKey(LocalNonce, RemoteNonce);
                PrevSecurityToken.ChannelId = 0;
                PrevSecurityToken.TokenId = 0;
                PrevSecurityToken.CreatedAt = DateTime.MinValue;
                PrevSecurityToken.RevisedLifetime = 0;
            }
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
                if (seqNum != _peerSequenceNumber.Value + 1)
                {
                    var wrapThreshold = uint.MaxValue - 1024;
                    var isWrap = seqNum < 1024 && _peerSequenceNumber.Value >= wrapThreshold;
                    if (!isWrap)
                    {

                    }
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

    public class OpenSecureChannelParameters
    {
        internal SecurityTokenRequestType RequestType { get; set; }
        internal MessageSecurityMode SecurityMode { get; set; }
        internal byte[] ClientNonce { get; set; }
        internal uint RequestedLifetime { get; set; }
    }

    public class OpenSecureChannelResult
    {
        internal uint ServerProtocolVersion { get; set; }
        internal ChannelSecurityToken SecurityToken { get; set; } = new ChannelSecurityToken();
        internal byte[]? ServerNonce { get; set; }
    }

    internal interface IServerContext
    {
        uint GetNewChannelId();
    }
}
