using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Transport
{
    internal class MessageChunk
    {
        private static BinaryEncoder RentEncoder() => BinaryEncoderPool.Rent();

        private static void ReturnEncoder(BinaryEncoder e) => BinaryEncoderPool.Return(e);

        internal Header MessageHeader { get; set; } = null!;
        internal ISecurityHeader SecurityHeader { get; set; } = null!;
        internal SequenceHeader SequenceHeader { get; set; } = new SequenceHeader();
        internal byte[] Body { get; set; } = Array.Empty<byte>();
        internal ICryptography Cryptography { get; }

        internal MessageChunk(ICryptography cryptography)
        {
            Cryptography = cryptography;
        }

        internal MessageChunk(SecurityPolicy securityPolicy, byte[]? body = null, byte[]? messageType = null, byte chunkType = ChunkType.Single)
            : this(securityPolicy.SymmetricCryptography)
        {
            messageType ??= MessageType.SecureMessage;
            MessageHeader = new Header(messageType, chunkType);

            if (MessageHeader.IsSecureOpen)
            {
                SecurityHeader = new AsymmetricAlgorithmHeader
                {
                    SecurityPolicyUri = securityPolicy.Uri,
                    SenderCertificate = securityPolicy.SenderCertificate,
                    ReceiverCertificateThumbprint = securityPolicy.ReceiverThumbprint
                };
                Cryptography = securityPolicy.AsymmetricCryptography;
            }
            else
            {
                SecurityHeader = new SymmetricAlgorithmHeader();
            }

            Body = body ?? Array.Empty<byte>();
        }

        internal static MessageChunk FromBinary(SecurityPolicy securityPolicy, BinaryDecoder decoder)
        {
            var header = Header.Decode(decoder);
            if (header.IsSecureMessage || header.IsSecureOpen || header.IsSecureClose)
            {
                header.ChannelId = decoder.ReadUInt32();
            }
            return FromHeaderAndBody(securityPolicy, header, decoder);
        }

        internal static MessageChunk FromHeaderAndBody(SecurityPolicy securityPolicy, Header header, BinaryDecoder decoder)
        {
            ICryptography crypto;
            ISecurityHeader securityHeader;

            if (header.IsSecureMessage || header.IsSecureClose)
            {
                securityHeader = SymmetricAlgorithmHeader.Decode(decoder);
                crypto = securityPolicy.SymmetricCryptography;
            }
            else if (header.IsSecureOpen)
            {
                securityHeader = AsymmetricAlgorithmHeader.Decode(decoder);
                crypto = securityPolicy.AsymmetricCryptography;
            }
            else
            {
                throw new UaException(0x80000000, $"Unsupported message type: {MessageType.ToString(header.MessageType)}");
            }

            var chunk = new MessageChunk(crypto)
            {
                MessageHeader = header,
                SecurityHeader = securityHeader
            };

            DecryptInto(chunk, decoder);
            return chunk;
        }

        /// <summary>
        /// Decrypts, verifies, and unpads the remaining payload of <paramref name="decoder"/>
        /// into the chunk's SequenceHeader and Body. This is the single receive-side unprotect
        /// pipeline, shared by chunk parsing and the client receive loop. The plaintext is
        /// processed via spans over the decrypted buffer — no signature/unpadded copies.
        /// </summary>
        internal static void DecryptInto(MessageChunk chunk, BinaryDecoder decoder)
        {
            if (decoder.Remaining <= 0)
                return;

            var crypto = chunk.Cryptography;
            if (crypto.RemoteSignatureSize > 0 && decoder.Remaining >= crypto.RemoteSignatureSize)
            {
                var decrypted = crypto.Decrypt(decoder.ReadRemainingSpan());

                int sigLen = crypto.RemoteSignatureSize;
                var plaintext = decrypted.AsSpan(0, decrypted.Length - sigLen);
                var signature = decrypted.AsSpan(decrypted.Length - sigLen);

                var headerBytes = EncodeHeaderToBytes(chunk.MessageHeader);
                var securityBytes = EncodeSecurityHeaderToBytes(chunk.SecurityHeader);
                crypto.Verify(headerBytes, securityBytes, plaintext, signature);

                int padSize = crypto.GetPaddingSize(plaintext);
                var bodyDecoder = new BinaryDecoder(decrypted, 0, plaintext.Length - padSize);
                chunk.SequenceHeader = SequenceHeader.Decode(bodyDecoder);
                chunk.Body = bodyDecoder.GetRemainingBytes();
            }
            else
            {
                // Unsecured (None / not yet keyed) payload: sequence header + body in the clear.
                chunk.SequenceHeader = SequenceHeader.Decode(decoder);
                chunk.Body = decoder.GetRemainingBytes();
            }
        }

        internal byte[] ToBinary()
        {

            if (Cryptography.SignatureSize == 0 && Cryptography.PlainBlockSize <= 1
                && SecurityHeader is SymmetricAlgorithmHeader sym)
            {

                int totalSize = 24 + Body.Length;
                var result = new byte[totalSize];

                var mt = MessageHeader.MessageType;
                result[0] = mt[0];
                result[1] = mt[1];
                result[2] = mt[2];
                result[3] = MessageHeader.ChunkType;

                int bodySize = 12 + Body.Length;
                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)(bodySize + 12));
                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), MessageHeader.ChannelId);

                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), sym.TokenId);

                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), SequenceHeader.SequenceNumber);
                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(20), SequenceHeader.RequestId);

                if (Body.Length > 0)
                    Buffer.BlockCopy(Body, 0, result, 24, Body.Length);

                MessageHeader.BodySize = bodySize;
                return result;
            }

            var encoder = RentEncoder();
            var securityEncoder = RentEncoder();
            var bodyEncoder = RentEncoder();
            try
            {
                SecurityHeader.Encode(securityEncoder);
                byte[] securityBytes = securityEncoder.ToByteArray();

                SequenceHeader.Encode(bodyEncoder);
                bodyEncoder.WriteBytes(Body);
                byte[] bodyBytes = bodyEncoder.ToByteArray();

                if (Cryptography.SignatureSize > 0 || Cryptography.PlainBlockSize > 1)
                {
                    var padding = Cryptography.Padding(bodyBytes.Length);
                    var paddedBody = new byte[bodyBytes.Length + padding.Length];
                    Array.Copy(bodyBytes, paddedBody, bodyBytes.Length);
                    Array.Copy(padding, 0, paddedBody, bodyBytes.Length, padding.Length);

                    int plainSize = paddedBody.Length + Cryptography.SignatureSize;
                    int encryptedSize = Cryptography.PlainBlockSize > 1
                        ? (plainSize / Cryptography.PlainBlockSize) * Cryptography.EncryptedBlockSize
                        : plainSize;

                    MessageHeader.BodySize = securityBytes.Length + encryptedSize;

                    MessageHeader.Encode(encoder);
                    byte[] headerBytes = encoder.ToByteArray();
                    encoder.Reset();

                    var signedData = new byte[headerBytes.Length + securityBytes.Length + paddedBody.Length];
                    Buffer.BlockCopy(headerBytes, 0, signedData, 0, headerBytes.Length);
                    Buffer.BlockCopy(securityBytes, 0, signedData, headerBytes.Length, securityBytes.Length);
                    Buffer.BlockCopy(paddedBody, 0, signedData, headerBytes.Length + securityBytes.Length, paddedBody.Length);
                    var signature = Cryptography.Sign(signedData);

                    if (SecurityDebugLogger.IsDebugEnabled && SecurityHeader is AsymmetricAlgorithmHeader asymForVerify)
                        OpnDiagnostics.SelfVerify(asymForVerify, signedData, signature);

                    var plaintextWithSig = new byte[paddedBody.Length + signature.Length];
                    Buffer.BlockCopy(paddedBody, 0, plaintextWithSig, 0, paddedBody.Length);
                    Buffer.BlockCopy(signature, 0, plaintextWithSig, paddedBody.Length, signature.Length);
                    var encrypted = Cryptography.Encrypt(plaintextWithSig);

                    encoder.WriteBytes(headerBytes);
                    encoder.WriteBytes(securityBytes);
                    encoder.WriteBytes(encrypted);

                    if (SecurityDebugLogger.IsDebugEnabled && SecurityHeader is AsymmetricAlgorithmHeader asymForLog)
                        OpnDiagnostics.LogToBinary(asymForLog, MessageHeader, Cryptography,
                            headerBytes, securityBytes, bodyBytes.Length, padding, signature,
                            encrypted, plainSize, encryptedSize, encoder.Length);
                }
                else
                {
                    MessageHeader.BodySize = securityBytes.Length + bodyBytes.Length;
                    MessageHeader.Encode(encoder);
                    encoder.WriteBytes(securityBytes);
                    encoder.WriteBytes(bodyBytes);
                }

                return encoder.ToByteArray();
            }
            finally
            {
                ReturnEncoder(encoder);
                ReturnEncoder(securityEncoder);
                ReturnEncoder(bodyEncoder);
            }
        }

        internal static int MaxBodySize(ICryptography crypto, int maxChunkSize)
        {
            var headerSize = 8 + 4;
            var symmetricHeaderSize = 4;
            var maxEncryptedSize = maxChunkSize - headerSize - symmetricHeaderSize;
            if (crypto.PlainBlockSize > 1)
            {
                var maxPlainSize = (maxEncryptedSize / crypto.EncryptedBlockSize) * crypto.PlainBlockSize;
                return maxPlainSize - 8 - crypto.SignatureSize - crypto.MinPaddingSize;
            }
            return maxEncryptedSize - 8 - crypto.SignatureSize;
        }

        internal static List<MessageChunk> MessageToChunks(
            SecurityPolicy securityPolicy,
            byte[] body,
            int maxChunkSize,
            byte[]? messageType = null,
            uint channelId = 1,
            uint requestId = 1,
            uint tokenId = 1)
            => MessageToChunks(securityPolicy, new ArraySegment<byte>(body), maxChunkSize,
                messageType, channelId, requestId, tokenId);

        internal static List<MessageChunk> MessageToChunks(
            SecurityPolicy securityPolicy,
            ArraySegment<byte> body,
            int maxChunkSize,
            byte[]? messageType = null,
            uint channelId = 1,
            uint requestId = 1,
            uint tokenId = 1)
        {
            messageType ??= MessageType.SecureMessage;
            var chunks = new List<MessageChunk>();

            if (MessageType.Equals(messageType, MessageType.SecureOpen))
            {
                var chunk = new MessageChunk(securityPolicy.AsymmetricCryptography)
                {
                    MessageHeader = new Header(MessageType.SecureOpen, ChunkType.Single),
                    SecurityHeader = new AsymmetricAlgorithmHeader
                    {
                        SecurityPolicyUri = securityPolicy.Uri,
                        SenderCertificate = securityPolicy.SenderCertificate,
                        ReceiverCertificateThumbprint = securityPolicy.ReceiverThumbprint
                    },
                    Body = SegmentToArray(body)
                };
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                return new List<MessageChunk> { chunk };
            }

            var crypto = securityPolicy.SymmetricCryptography;
            // OPC UA Part 6 mandates a minimum negotiated buffer of 8192 bytes. Clamp to that
            // floor so a too-small or not-yet-negotiated maxChunkSize can't yield a non-positive
            // body limit — the previous hardcoded 65536 fallback produced chunks larger than the
            // channel's actual buffer, which a conformant server rejects.
            var maxSize = MaxBodySize(crypto, Math.Max(maxChunkSize, 8192));
            if (maxSize <= 0) maxSize = MaxBodySize(crypto, 8192);

            if (body.Count <= maxSize)
            {
                var chunk = new MessageChunk(securityPolicy, SegmentToArray(body), messageType, ChunkType.Single);
                ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = tokenId;
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                chunks.Add(chunk);
                return chunks;
            }

            for (int offset = 0; offset < body.Count; offset += maxSize)
            {
                var remaining = body.Count - offset;
                var chunkSize = Math.Min(remaining, maxSize);
                var chunkBody = new byte[chunkSize];
                Buffer.BlockCopy(body.Array!, body.Offset + offset, chunkBody, 0, chunkSize);

                var isLast = offset + maxSize >= body.Count;
                var chunkType = isLast ? ChunkType.Single : ChunkType.Intermediate;

                var chunk = new MessageChunk(securityPolicy, chunkBody, messageType, chunkType);
                ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = tokenId;
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                chunks.Add(chunk);
            }

            return chunks;
        }

        /// <summary>
        /// Returns the segment contents as an array, sharing the underlying array when the segment
        /// covers it entirely. Callers consume the result synchronously (before any pooled buffer
        /// backing the segment is reused), so sharing is safe.
        /// </summary>
        private static byte[] SegmentToArray(ArraySegment<byte> segment)
        {
            if (segment.Array == null || segment.Count == 0) return Array.Empty<byte>();
            if (segment.Offset == 0 && segment.Count == segment.Array.Length) return segment.Array;
            var copy = new byte[segment.Count];
            Buffer.BlockCopy(segment.Array, segment.Offset, copy, 0, segment.Count);
            return copy;
        }

        public override string ToString()
        {
            return $"MessageChunk({MessageHeader}, {SequenceHeader}, {Body.Length} bytes)";
        }

        internal static byte[] EncodeHeaderToBytes(Header header)
        {
            var enc = RentEncoder();
            try
            {
                header.Encode(enc);
                return enc.ToByteArray();
            }
            finally { ReturnEncoder(enc); }
        }

        internal static byte[] EncodeSecurityHeaderToBytes(ISecurityHeader securityHeader)
        {
            var enc = RentEncoder();
            try
            {
                securityHeader.Encode(enc);
                return enc.ToByteArray();
            }
            finally { ReturnEncoder(enc); }
        }
    }

    internal class Message
    {
        private readonly List<MessageChunk> _chunks;
        private byte[]? _body;

        internal Message(List<MessageChunk> chunks)
        {
            _chunks = chunks ?? new List<MessageChunk>();
        }

        internal byte[]? MessageType => _chunks.Count > 0 ? _chunks[0].MessageHeader.MessageType : null;
        internal uint RequestId => _chunks.Count > 0 ? _chunks[0].SequenceHeader.RequestId : 0;
        internal SequenceHeader? SequenceHeader => _chunks.Count > 0 ? _chunks[0].SequenceHeader : null;
        internal ISecurityHeader? SecurityHeader => _chunks.Count > 0 ? _chunks[0].SecurityHeader : null;

        internal byte[] Body => _body ??= BuildBody();

        private byte[] BuildBody()
        {
            if (_chunks.Count == 1)
                return _chunks[0].Body;

            var totalSize = 0;
            foreach (var chunk in _chunks)
                totalSize += chunk.Body.Length;

            var body = new byte[totalSize];
            var offset = 0;
            foreach (var chunk in _chunks)
            {
                Buffer.BlockCopy(chunk.Body, 0, body, offset, chunk.Body.Length);
                offset += chunk.Body.Length;
            }
            return body;
        }

        public override string ToString()
        {
            return $"Message(Chunks={_chunks.Count}, RequestId={RequestId})";
        }
    }
}
