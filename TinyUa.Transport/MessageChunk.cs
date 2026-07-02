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

namespace TinyUa.Core.Transport
{
    internal class MessageChunk
    {
        private static readonly System.Collections.Concurrent.ConcurrentBag<BinaryEncoder> s_encoderPool = new();

        private static BinaryEncoder RentEncoder()
        {
            if (s_encoderPool.TryTake(out var e)) { e.Reset(); return e; }
            return new BinaryEncoder();
        }

        private static void ReturnEncoder(BinaryEncoder e) => s_encoderPool.Add(e);

        internal Header MessageHeader { get; set; } = null!;
        internal object SecurityHeader { get; set; } = null!;
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
            object securityHeader;

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

            var remaining = decoder.Remaining;
            if (remaining > 0)
            {
                var encryptedData = decoder.ReadBytes(remaining);

                if (crypto.RemoteSignatureSize > 0 && encryptedData.Length >= crypto.RemoteSignatureSize)
                {
                    var decrypted = crypto.Decrypt(encryptedData);

                    int sigLen = crypto.RemoteSignatureSize;
                    var signature = decrypted[^sigLen..];
                    var plaintext = decrypted[..^sigLen];

                    var headerBytes = EncodeHeaderToBytes(header);
                    var securityBytes = EncodeSecurityHeaderToBytes(securityHeader);
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

            return chunk;
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
                if (SecurityHeader is SymmetricAlgorithmHeader sym2)
                    sym2.Encode(securityEncoder);
                else if (SecurityHeader is AsymmetricAlgorithmHeader asym)
                    asym.Encode(securityEncoder);
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

                    if (SecurityHeader is AsymmetricAlgorithmHeader asymForVerify)
                    {
                        try
                        {
                            using var senderCert = new X509Certificate2(asymForVerify.SenderCertificate);
                            using var senderPublicKey = senderCert.GetRSAPublicKey();
                            if (senderPublicKey != null)
                            {
                                var policyUri = asymForVerify.SecurityPolicyUri ?? "";
                                bool isPss = policyUri.Contains("Aes256");
                                var sigHash = HashAlgorithmName.SHA256;
                                var sigPadding = isPss
                                    ? RSASignaturePadding.Pss
                                    : RSASignaturePadding.Pkcs1;
                                bool sigValid = senderPublicKey.VerifyData(
                                    signedData, signature, sigHash, sigPadding);
                                SecurityDebugLogger.LogStage("OPN.SelfVerify",
                                    ("sigValid", sigValid),
                                    ("senderCertSubject", senderCert.Subject),
                                    ("senderCertThumbprint", senderCert.Thumbprint),
                                    ("senderPublicKeySize", senderPublicKey.KeySize),
                                    ("signedDataLen", signedData.Length),
                                    ("signatureLen", signature.Length),
                                    ("sigPadding", isPss ? "Pss" : "Pkcs1"));
                            }
                        }
                        catch (Exception ex)
                        {
                            SecurityDebugLogger.LogStage("OPN.SelfVerify",
                                ("error", ex.GetType().Name + ": " + ex.Message));
                        }
                    }

                    var plaintextWithSig = new byte[paddedBody.Length + signature.Length];
                    Buffer.BlockCopy(paddedBody, 0, plaintextWithSig, 0, paddedBody.Length);
                    Buffer.BlockCopy(signature, 0, plaintextWithSig, paddedBody.Length, signature.Length);
                    var encrypted = Cryptography.Encrypt(plaintextWithSig);

                    if (SecurityHeader is AsymmetricAlgorithmHeader asymForEnc)
                    {
                        try
                        {
                            using var localPriv = RSA.Create(2048);
                            using var localPub = localPriv;
                            var policyUri = asymForEnc.SecurityPolicyUri ?? "";
                            bool isPssEnc = policyUri.Contains("Aes256");
                            var encPadding = isPssEnc
                                ? RSAEncryptionPadding.OaepSHA256
                                : RSAEncryptionPadding.OaepSHA1;
                            int oaepOverhead = isPssEnc ? 66 : 42;
                            int keyBytes = localPub.KeySize / 8;
                            int plainBlk = keyBytes - oaepOverhead;

                            int blkCount = (plaintextWithSig.Length + plainBlk - 1) / plainBlk;
                            var reEncrypted = new byte[blkCount * keyBytes];
                            var blk = new byte[plainBlk];
                            for (int i = 0; i < blkCount; i++)
                            {
                                int off = i * plainBlk;
                                int len = Math.Min(plainBlk, plaintextWithSig.Length - off);
                                Buffer.BlockCopy(plaintextWithSig, off, blk, 0, len);
                                var enc = len == plainBlk
                                    ? localPub.Encrypt(blk, encPadding)
                                    : localPub.Encrypt(blk.AsSpan(0, len).ToArray(), encPadding);
                                Buffer.BlockCopy(enc, 0, reEncrypted, i * keyBytes, keyBytes);
                            }

                            using var ms = new System.IO.MemoryStream(blkCount * plainBlk);
                            var decBlk = new byte[keyBytes];
                            for (int i = 0; i < blkCount; i++)
                            {
                                Buffer.BlockCopy(reEncrypted, i * keyBytes, decBlk, 0, keyBytes);
                                var dec = localPriv.Decrypt(decBlk, encPadding);
                                ms.Write(dec, 0, dec.Length);
                            }
                            var reDecrypted = ms.ToArray();

                            bool roundTripOk = reDecrypted.Length == plaintextWithSig.Length;
                            for (int i = 0; i < reDecrypted.Length && roundTripOk; i++)
                                roundTripOk = reDecrypted[i] == plaintextWithSig[i];

                            SecurityDebugLogger.LogStage("OPN.EncRoundTrip",
                                ("roundTripOk", roundTripOk),
                                ("origLen", plaintextWithSig.Length),
                                ("decryptedLen", reDecrypted.Length),
                                ("blockCount", blkCount),
                                ("plainBlk", plainBlk),
                                ("keyBytes", keyBytes),
                                ("encPadding", isPssEnc ? "OaepSHA256" : "OaepSHA1"));
                        }
                        catch (Exception ex)
                        {
                            SecurityDebugLogger.LogStage("OPN.EncRoundTrip",
                                ("error", ex.GetType().Name + ": " + ex.Message));
                        }
                    }

                    encoder.WriteBytes(headerBytes);
                    encoder.WriteBytes(securityBytes);
                    encoder.WriteBytes(encrypted);

                    if (SecurityHeader is AsymmetricAlgorithmHeader asymForLog)
                    {
                        var finalMessage = encoder.ToByteArray();
                        var uriForLog = asymForLog.SecurityPolicyUri ?? "";
                        var certForLog = asymForLog.SenderCertificate;
                        var thumbForLog = asymForLog.ReceiverCertificateThumbprint;
                        int uriByteLen = System.Text.Encoding.UTF8.GetByteCount(uriForLog);
                        SecurityDebugLogger.LogStage("OPN.ToBinary",
                            ("headerLen", headerBytes.Length),
                            ("securityLen", securityBytes.Length),
                            ("bodyLen", bodyBytes.Length),
                            ("paddingLen", padding.Length),
                            ("sigLen", signature.Length),
                            ("plainBlockSize", Cryptography.PlainBlockSize),
                            ("encryptedBlockSize", Cryptography.EncryptedBlockSize),
                            ("plainSize", plainSize),
                            ("encryptedSize", encryptedSize),
                            ("totalMsgLen", finalMessage.Length),
                            ("messageSizeInHeader", MessageHeader.BodySize + 12),
                            ("channelIdInHeader", MessageHeader.ChannelId),
                            ("uriStrLen", uriForLog.Length),
                            ("uriByteLen", uriByteLen),
                            ("senderCertLen", certForLog?.Length ?? -1),
                            ("thumbprintLen", thumbForLog?.Length ?? -1),
                            ("expectedSecurityLen", 4 + uriByteLen + 4 + (certForLog?.Length ?? 0) + 4 + (thumbForLog?.Length ?? 0)));
                        SecurityDebugLogger.LogHexDump("OPN.header", headerBytes, 64);
                        SecurityDebugLogger.LogHexDump("OPN.security", securityBytes, 200);
                        SecurityDebugLogger.LogHexDump("OPN.senderCert", certForLog, 64);
                        SecurityDebugLogger.LogHexDump("OPN.thumbprint", thumbForLog, 32);
                        SecurityDebugLogger.LogHexDump("OPN.padding", padding, 32);
                        SecurityDebugLogger.LogHexDump("OPN.encryptedFirst256", encrypted, 256);
                    }
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
                    Body = body
                };
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                return new List<MessageChunk> { chunk };
            }

            var crypto = securityPolicy.SymmetricCryptography;
            var maxSize = MaxBodySize(crypto, maxChunkSize);
            if (maxSize <= 0) maxSize = 65536;

            if (body.Length <= maxSize)
            {
                var chunk = new MessageChunk(securityPolicy, body, messageType, ChunkType.Single);
                ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = tokenId;
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                chunks.Add(chunk);
                return chunks;
            }

            for (int offset = 0; offset < body.Length; offset += maxSize)
            {
                var remaining = body.Length - offset;
                var chunkSize = Math.Min(remaining, maxSize);
                var chunkBody = new byte[chunkSize];
                Array.Copy(body, offset, chunkBody, 0, chunkSize);

                var isLast = offset + maxSize >= body.Length;
                var chunkType = isLast ? ChunkType.Single : ChunkType.Intermediate;

                var chunk = new MessageChunk(securityPolicy, chunkBody, messageType, chunkType);
                ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = tokenId;
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                chunks.Add(chunk);
            }

            if (chunks.Count == 0)
            {
                var chunk = new MessageChunk(securityPolicy, Array.Empty<byte>(), messageType, ChunkType.Single);
                ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = tokenId;
                chunk.MessageHeader.ChannelId = channelId;
                chunk.SequenceHeader.RequestId = requestId;
                chunks.Add(chunk);
            }

            return chunks;
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

        internal static byte[] EncodeSecurityHeaderToBytes(object securityHeader)
        {
            var enc = RentEncoder();
            try
            {
                if (securityHeader is SymmetricAlgorithmHeader sym)
                    sym.Encode(enc);
                else if (securityHeader is AsymmetricAlgorithmHeader asym)
                    asym.Encode(enc);
                else
                    throw new InvalidOperationException($"Unknown security header type: {securityHeader?.GetType()}");
                return enc.ToByteArray();
            }
            finally { ReturnEncoder(enc); }
        }
    }

    internal class Message
    {
        private readonly List<MessageChunk> _chunks;

        internal Message(List<MessageChunk> chunks)
        {
            _chunks = chunks ?? new List<MessageChunk>();
        }

        internal byte[]? MessageType => _chunks.Count > 0 ? _chunks[0].MessageHeader.MessageType : null;
        internal uint RequestId => _chunks.Count > 0 ? _chunks[0].SequenceHeader.RequestId : 0;
        internal SequenceHeader? SequenceHeader => _chunks.Count > 0 ? _chunks[0].SequenceHeader : null;
        internal object? SecurityHeader => _chunks.Count > 0 ? _chunks[0].SecurityHeader : null;

        internal byte[] Body
        {
            get
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
                    Array.Copy(chunk.Body, 0, body, offset, chunk.Body.Length);
                    offset += chunk.Body.Length;
                }
                return body;
            }
        }

        public override string ToString()
        {
            return $"Message(Chunks={_chunks.Count}, RequestId={RequestId})";
        }
    }
}
