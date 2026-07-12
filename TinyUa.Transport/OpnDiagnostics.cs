using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Transport
{
    /// <summary>
    /// Debug-only diagnostics for OpenSecureChannel message construction, kept out of the
    /// <see cref="MessageChunk.ToBinary"/> hot path. Callers gate every call on
    /// <see cref="SecurityDebugLogger.IsDebugEnabled"/>.
    /// </summary>
    internal static class OpnDiagnostics
    {
        /// <summary>
        /// Re-verifies the just-produced asymmetric signature with the sender's own public key,
        /// to distinguish "we signed it wrong" from "the server rejected it for another reason".
        /// </summary>
        internal static void SelfVerify(AsymmetricAlgorithmHeader header, byte[] signedData, byte[] signature)
        {
            try
            {
                if (header.SenderCertificate == null) return;
                using var senderCert = new X509Certificate2(header.SenderCertificate);
                using var senderPublicKey = senderCert.GetRSAPublicKey();
                if (senderPublicKey == null) return;

                var policyUri = header.SecurityPolicyUri ?? "";
                bool isPss = policyUri.Contains("Aes256");
                var sigPadding = isPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                bool sigValid = senderPublicKey.VerifyData(
                    signedData, signature, HashAlgorithmName.SHA256, sigPadding);
                SecurityDebugLogger.LogStage("OPN.SelfVerify",
                    ("sigValid", sigValid),
                    ("senderCertSubject", senderCert.Subject),
                    ("senderCertThumbprint", senderCert.Thumbprint),
                    ("senderPublicKeySize", senderPublicKey.KeySize),
                    ("signedDataLen", signedData.Length),
                    ("signatureLen", signature.Length),
                    ("sigPadding", isPss ? "Pss" : "Pkcs1"));
            }
            catch (Exception ex)
            {
                SecurityDebugLogger.LogStage("OPN.SelfVerify",
                    ("error", ex.GetType().Name + ": " + ex.Message));
            }
        }

        internal static void LogToBinary(
            AsymmetricAlgorithmHeader header,
            Header messageHeader,
            ICryptography crypto,
            byte[] headerBytes,
            byte[] securityBytes,
            int bodyLen,
            byte[] padding,
            byte[] signature,
            byte[] encrypted,
            int plainSize,
            int encryptedSize,
            int totalMsgLen)
        {
            var uri = header.SecurityPolicyUri ?? "";
            var cert = header.SenderCertificate;
            var thumb = header.ReceiverCertificateThumbprint;
            int uriByteLen = System.Text.Encoding.UTF8.GetByteCount(uri);
            SecurityDebugLogger.LogStage("OPN.ToBinary",
                ("headerLen", headerBytes.Length),
                ("securityLen", securityBytes.Length),
                ("bodyLen", bodyLen),
                ("paddingLen", padding.Length),
                ("sigLen", signature.Length),
                ("plainBlockSize", crypto.PlainBlockSize),
                ("encryptedBlockSize", crypto.EncryptedBlockSize),
                ("plainSize", plainSize),
                ("encryptedSize", encryptedSize),
                ("totalMsgLen", totalMsgLen),
                ("messageSizeInHeader", messageHeader.BodySize + 12),
                ("channelIdInHeader", messageHeader.ChannelId),
                ("uriStrLen", uri.Length),
                ("uriByteLen", uriByteLen),
                ("senderCertLen", cert?.Length ?? -1),
                ("thumbprintLen", thumb?.Length ?? -1),
                ("expectedSecurityLen", 4 + uriByteLen + 4 + (cert?.Length ?? 0) + 4 + (thumb?.Length ?? 0)));
            SecurityDebugLogger.LogHexDump("OPN.header", headerBytes, 64);
            SecurityDebugLogger.LogHexDump("OPN.security", securityBytes, 200);
            SecurityDebugLogger.LogHexDump("OPN.senderCert", cert, 64);
            SecurityDebugLogger.LogHexDump("OPN.thumbprint", thumb, 32);
            SecurityDebugLogger.LogHexDump("OPN.padding", padding, 32);
            SecurityDebugLogger.LogHexDump("OPN.encryptedFirst256", encrypted, 256);
        }
    }
}
