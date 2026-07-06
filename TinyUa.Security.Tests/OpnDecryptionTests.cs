using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Security.Certificates;
using TinyUa.Transport;
using TinyUa.Core.Types;
using Xunit;
using Xunit.Abstractions;

namespace TinyUa.Security.Tests;

/// <summary>
/// Direct decryption / verification test that reproduces the OPCF server-side
/// <c>ReadAsymmetricMessage</c> pipeline against TinyUa's OPN wire bytes, using the
/// server's ACTUAL private key from <see cref="OpcfSecureServerFixture.ServerCertificate"/>.
///
/// This isolates the OPN failure (0x80130000 "Could not verify security on
/// OpenSecureChannel request") into exactly one of three buckets:
///
///   (a) <b>Decryption failure</b> — server's private key cannot decrypt the encrypted
///       blob. Cause would be: wrong OAEP padding, wrong block-split, wrong recipient
///       key, or wrong thumbprint lookup.
///   (b) <b>Signature failure</b> — decryption succeeds but signature verification using
///       the public key from the OPN SenderCertificate fails. Cause would be: wrong
///       signed-region bytes, wrong signature padding (Pkcs1 vs Pss), or wrong hash.
///   (c) <b>Neither</b> — both decryption and signature verification succeed in this
///       isolated test, which means the bug is in something this test does NOT
///       reproduce: e.g. certificate validation (CertValidator rejecting the client
///       cert for missing SKI, EKU mismatch, hostname mismatch), or padding removal,
///       or body decoding.
///
/// The test uses TinyUa's INTERNAL APIs (reachable via InternalsVisibleTo) to build the
/// OPN message identically to how <c>UaClient</c> builds it on the wire.
/// </summary>
[Collection("SecureServer")]
public sealed class OpnDecryptionTests
{
    private readonly OpcfSecureServerFixture _fixture;
    private readonly ITestOutputHelper _output;

    public OpnDecryptionTests(OpcfSecureServerFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task DirectDecrypt_VerifyWithServerPrivateKey_Basic256Sha256()
    {
        // ---- 1. Verify the fixture's server cert has a private key -----------------
        // The fixture loads the cert from a directory cert store via
        // ApplicationInstance.CheckApplicationInstanceCertificate. On Windows that
        // produces an X509Certificate2 WITH the private key attached.
        var serverCert = _fixture.ServerCertificate;
        Assert.NotNull(serverCert);
        _output.WriteLine($"[Step 1] ServerCert Subject: {serverCert!.Subject}");
        _output.WriteLine($"[Step 1] ServerCert Thumbprint: {serverCert.Thumbprint}");
        _output.WriteLine($"[Step 1] ServerCert.HasPrivateKey: {serverCert.HasPrivateKey}");

        using var serverRsaPriv = serverCert.GetRSAPrivateKey();
        Assert.NotNull(serverRsaPriv);
        _output.WriteLine($"[Step 1] ServerCert RSA key size: {serverRsaPriv!.KeySize} bits");

        using var serverRsaPub = serverCert.GetRSAPublicKey();
        Assert.NotNull(serverRsaPub);
        _output.WriteLine($"[Step 1] ServerCert public key size: {serverRsaPub!.KeySize} bits");

        // ---- 2. Generate a client cert with private key (same path as UaClient) ---
        var (clientCert, clientRsaPriv) = CertificateGenerator.CreateSelfSigned(
            applicationName: "TinyUa-DecryptTest",
            applicationUri: "urn:tinyua:decrypttest",
            keySize: 2048,
            validityYears: 1);
        using (clientRsaPriv) { }
        _output.WriteLine($"[Step 2] ClientCert Subject: {clientCert.Subject}");
        _output.WriteLine($"[Step 2] ClientCert Thumbprint: {clientCert.Thumbprint}");
        _output.WriteLine($"[Step 2] ClientCert.HasPrivateKey: {clientCert.HasPrivateKey}");

        using var clientRsaPrivCheck = clientCert.GetRSAPrivateKey();
        Assert.NotNull(clientRsaPrivCheck);
        _output.WriteLine($"[Step 2] ClientCert RSA key size: {clientRsaPrivCheck!.KeySize} bits");

        // ---- 3. Create the SecurityPolicy (asymmetric layer = SignAndEncrypt) ------
        // This is the same call UaClient makes internally.
        var policy = SecurityPolicyFactory.Create(
            "Basic256Sha256",
            clientCert,
            serverCert,
            MessageSecurityMode.SignAndEncrypt);
        _output.WriteLine($"[Step 3] Policy.Uri: {policy.Uri}");
        _output.WriteLine($"[Step 3] Policy.SenderCertificate.Length: {policy.SenderCertificate?.Length ?? -1}");
        _output.WriteLine($"[Step 3] Policy.ReceiverThumbprint (hex): {ToHex(policy.ReceiverThumbprint)}");
        _output.WriteLine($"[Step 3] Policy.AsymmetricSignatureSize: {policy.AsymmetricSignatureSize}");

        // Cross-check: the ReceiverThumbprint in the OPN header must equal the SHA-1
        // of the server cert's RawData. The server looks up its key by this thumbprint.
        using var sha1 = SHA1.Create();
        var expectedThumb = sha1.ComputeHash(serverCert.RawData);
        _output.WriteLine($"[Step 3] Expected thumbprint (SHA-1 of serverCert.RawData): {ToHex(expectedThumb)}");
        Assert.Equal(expectedThumb, policy.ReceiverThumbprint);

        // ---- 4. Build the OPN message via TinyUa's MessageChunk pipeline -----------
        // Use a representative OPN body (OpenSecureChannelRequest). For the purposes of
        // this test we only need a body of plausible length — the decryption/verification
        // logic doesn't inspect body contents.
        var opnBody = BuildDummyOpenSecureChannelRequestBody();
        _output.WriteLine($"[Step 4] OPN body length: {opnBody.Length} bytes");

        // Set the AsyncLocal logger so SecurityDebugLogger captures the OPN.ToBinary
        // instrumentation output during chunk construction.
        var logger = new DelegateLogger((level, ex, msg) =>
        {
            _output.WriteLine($"[TinyUa {level}] {msg}" + (ex != null ? $" | {ex.GetType().Name}: {ex.Message}" : ""));
        }, LogLevel.Debug);
        var previousLogger = SecurityDebugLogger.Current;
        SecurityDebugLogger.SetCurrentLogger(logger);
        try
        {
            var chunks = MessageChunk.MessageToChunks(
                policy,
                body: opnBody,
                maxChunkSize: 8192,
                messageType: MessageType.SecureOpen,
                channelId: 1,
                requestId: 1,
                tokenId: 1);
            Assert.Single(chunks);
            var wire = chunks[0].ToBinary();
            _output.WriteLine($"[Step 4] Wire OPN message length: {wire.Length} bytes");

            // ---- 5. Parse wire bytes: header + security header + encrypted blob --
            // Header layout (OPC UA Part 6, 7.5.1):
            //   MessageType(3) + ChunkType(1) + MessageSize(4) + ChannelId(4) = 12 bytes
            // SecurityHeader (AsymmetricAlgorithmHeader, Part 6, 7.5.2):
            //   SecurityPolicyUri(4+N) + SenderCertificate(4+N) + ReceiverThumbprint(4+N)
            // Remaining: encrypted(SequenceHeader + Body + Padding + Signature)

            int offset = 0;
            string mt = Encoding.ASCII.GetString(wire, 0, 3);
            byte chunkType = wire[3];
            uint messageSize = BitConverter.ToUInt32(wire, 4);
            uint channelId = BitConverter.ToUInt32(wire, 8);
            offset = 12;
            _output.WriteLine($"[Step 5] MessageType={mt}, ChunkType={(char)chunkType}, MessageSize={messageSize}, ChannelId={channelId}");
            Assert.Equal("OPN", mt);
            Assert.Equal(messageSize, (uint)wire.Length);

            // Security header
            string policyUri = ReadString(wire, ref offset);
            byte[] senderCert = ReadByteString(wire, ref offset);
            byte[] receiverThumb = ReadByteString(wire, ref offset);
            _output.WriteLine($"[Step 5] PolicyUri: {policyUri} (len={policyUri.Length})");
            _output.WriteLine($"[Step 5] SenderCertificate.Length: {senderCert.Length}");
            _output.WriteLine($"[Step 5] ReceiverThumbprint (hex): {ToHex(receiverThumb)} (len={receiverThumb.Length})");

            // Validate SenderCertificate matches what we put in the policy
            Assert.Equal(policy.SenderCertificate, senderCert);
            Assert.Equal(policy.ReceiverThumbprint, receiverThumb);

            // Encrypted blob = everything remaining
            byte[] encrypted = wire[offset..];
            _output.WriteLine($"[Step 5] Encrypted blob length: {encrypted.Length} bytes (offset={offset})");
            _output.WriteLine($"[Step 5] Encrypted first 32 bytes (hex): {ToHex(encrypted, 32)}");

            // The encrypted blob must be a multiple of the server's RSA key size (256 bytes
            // for 2048-bit) since TinyUa encrypts block-by-block with the REMOTE public key.
            int serverKeyBytes = serverRsaPriv.KeySize / 8;
            Assert.Equal(0, encrypted.Length % serverKeyBytes);
            int blockCount = encrypted.Length / serverKeyBytes;
            _output.WriteLine($"[Step 5] Block count: {blockCount} (keyBytes={serverKeyBytes})");

            // ---- 6. DECRYPT each block with the SERVER's private key ------------
            // This is exactly what OPCF's Rsa_Decrypt does. OAEP-SHA1 for Basic256Sha256.
            var oaepPadding = RSAEncryptionPadding.OaepSHA1;
            int oaepOverhead = 42; // SHA-1 OAEP
            int plainBlk = serverKeyBytes - oaepOverhead;

            byte[] decrypted;
            try
            {
                using var ms = new System.IO.MemoryStream(blockCount * plainBlk);
                var block = new byte[serverKeyBytes];
                for (int i = 0; i < blockCount; i++)
                {
                    Buffer.BlockCopy(encrypted, i * serverKeyBytes, block, 0, serverKeyBytes);
                    var dec = serverRsaPriv.Decrypt(block, oaepPadding);
                    ms.Write(dec, 0, dec.Length);
                }
                decrypted = ms.ToArray();
                _output.WriteLine($"[Step 6] DECRYPT SUCCEEDED. Decrypted length: {decrypted.Length} bytes");
                _output.WriteLine($"[Step 6] Decrypted first 32 bytes (hex): {ToHex(decrypted, 32)}");
                _output.WriteLine($"[Step 6] Decrypted last 32 bytes (hex): {ToHex(decrypted, decrypted.Length - 32, 32)}");
            }
            catch (CryptographicException ex)
            {
                _output.WriteLine($"[Step 6] DECRYPT FAILED: {ex.GetType().Name}: {ex.Message}");
                _output.WriteLine($"=== CONCLUSION: Bucket (a) Decryption failure ===");
                _output.WriteLine($"  The server's private key cannot decrypt the OPN encrypted blob.");
                _output.WriteLine($"  Suspects: wrong OAEP hash, wrong recipient key, wrong thumbprint lookup.");
                Assert.Fail("Decryption with server's private key failed — bug is in encryption pipeline.");
                return;
            }

            // ---- 7. SPLIT signature from the end of the decrypted data ----------
            // The signature was produced by the client's private key, so its length is
            // the CLIENT's key size (256 bytes for 2048-bit). This is what OPCF's
            // GetAsymmetricSignatureSize returns: RsaUtils.GetSignatureLength(senderCertificate).
            int sigLen = clientRsaPrivCheck.KeySize / 8;
            Assert.True(decrypted.Length >= sigLen,
                $"Decrypted data ({decrypted.Length}B) is smaller than signature ({sigLen}B).");
            byte[] signature = decrypted[^sigLen..];
            byte[] paddedBody = decrypted[..^sigLen];
            _output.WriteLine($"[Step 7] Signature length: {sigLen} bytes");
            _output.WriteLine($"[Step 7] PaddedBody length: {paddedBody.Length} bytes");
            _output.WriteLine($"[Step 7] Signature (hex): {ToHex(signature, 32)}...");
            _output.WriteLine($"[Step 7] PaddedBody first 16 bytes (hex): {ToHex(paddedBody, 16)}");
            _output.WriteLine($"[Step 7] PaddedBody last 16 bytes (hex): {ToHex(paddedBody, paddedBody.Length - 16, 16)}");

            // ---- 8. VERIFY the signature using the SenderCertificate's public key -
            // The server extracts the public key from the OPN's SenderCertificate (DER bytes)
            // and verifies the signature over (header + security + paddedBody).
            // This is the EXACT data region TinyUa signed — confirmed by reading OPCF's
            // ReadAsymmetricMessage: dataToVerify = headerToCopy + paddedBody where
            // headerToCopy = message header (12B) + security header bytes.
            using var senderCertParsed = new X509Certificate2(senderCert);
            using var senderPubKey = senderCertParsed.GetRSAPublicKey();
            Assert.NotNull(senderPubKey);
            _output.WriteLine($"[Step 8] SenderCert parsed. Subject: {senderCertParsed.Subject}, KeySize: {senderPubKey!.KeySize}");

            // Reconstruct the header + security bytes that the server uses as part of
            // dataToVerify. We need to re-encode them identically to TinyUa's wire format.
            byte[] headerBytes = wire[0..12];
            byte[] securityBytes = wire[12..offset]; // security header bytes (from offset 12 to start of encrypted)
            byte[] dataToVerify = new byte[headerBytes.Length + securityBytes.Length + paddedBody.Length];
            Buffer.BlockCopy(headerBytes, 0, dataToVerify, 0, headerBytes.Length);
            Buffer.BlockCopy(securityBytes, 0, dataToVerify, headerBytes.Length, securityBytes.Length);
            Buffer.BlockCopy(paddedBody, 0, dataToVerify, headerBytes.Length + securityBytes.Length, paddedBody.Length);
            _output.WriteLine($"[Step 8] dataToVerify length: {dataToVerify.Length} bytes " +
                              $"(header={headerBytes.Length} + security={securityBytes.Length} + paddedBody={paddedBody.Length})");

            // Basic256Sha256 uses PKCS1-SHA256 for asymmetric signatures.
            bool sigValid = senderPubKey.VerifyData(
                dataToVerify, signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            _output.WriteLine($"[Step 8] Signature verification result: {sigValid}");

            if (!sigValid)
            {
                _output.WriteLine($"=== CONCLUSION: Bucket (b) Signature failure ===");
                _output.WriteLine($"  Decryption succeeded but signature verification failed.");
                _output.WriteLine($"  Suspects: wrong signed-region bytes, wrong sig padding (Pkcs1/Pss), wrong hash.");
                Assert.Fail("Signature verification with SenderCertificate's public key failed.");
                return;
            }

            // ---- 9. Inspect padding (OPC UA Part 6, 6.7.2.3) --------------------
            // For 2048-bit keys (keyBytes<=256), the format is 1-byte length encoding:
            //   final byte = N (number of padding bytes minus 1)
            //   preceded by N bytes each with value N
            // All padding bytes (including the length byte) have the SAME value.
            int lastPadByte = paddedBody[^1];
            int padCount = lastPadByte + 1; // includes the length byte itself
            _output.WriteLine($"[Step 9] Padding last byte value: 0x{lastPadByte:X2} ({lastPadByte})");
            _output.WriteLine($"[Step 9] Padding total length: {padCount} bytes");

            // Verify all padding bytes have the same value
            bool paddingValid = true;
            for (int i = 0; i < padCount; i++)
            {
                if (paddedBody[paddedBody.Length - 1 - i] != lastPadByte)
                {
                    paddingValid = false;
                    _output.WriteLine($"[Step 9] Padding mismatch at index {paddedBody.Length - 1 - i}: " +
                                      $"expected 0x{lastPadByte:X2}, got 0x{paddedBody[paddedBody.Length - 1 - i]:X2}");
                    break;
                }
            }
            _output.WriteLine($"[Step 9] Padding bytes all-equal: {paddingValid}");

            // Show the body region (before padding)
            int bodyStart = 8; // SequenceHeader is 8 bytes (SequenceNumber:4 + RequestId:4)
            int bodyEnd = paddedBody.Length - padCount;
            _output.WriteLine($"[Step 9] SequenceHeader (first 8 bytes, hex): {ToHex(paddedBody, 8)}");
            _output.WriteLine($"[Step 9] Body length (after SeqHeader, before padding): {bodyEnd - bodyStart} bytes");
            _output.WriteLine($"[Step 9] Body first 16 bytes (hex): {ToHex(paddedBody, bodyStart, 16)}");

            _output.WriteLine("");
            _output.WriteLine("=== CONCLUSION: Bucket (c) Neither decryption nor signature failure ===");
            _output.WriteLine("  Both decryption (with server's private key) and signature verification");
            _output.WriteLine("  (with client's public key from SenderCertificate) SUCCEEDED in this test.");
            _output.WriteLine("  The bug must therefore be in something this test does NOT reproduce:");
            _output.WriteLine("    - Certificate validation (missing SKI extension, EKU mismatch, hostname)");
            _output.WriteLine("    - Padding-removal edge cases (this test verified padding is well-formed)");
            _output.WriteLine("    - Body decoding (OpenSecureChannelRequest parsing)");
            _output.WriteLine("    - SequenceNumber / RequestId validation");
            _output.WriteLine("  Next step: run an OPCF CertificateValidator against the client cert.");

            Assert.True(sigValid, "Signature must be valid");
            Assert.True(paddingValid, "Padding must be well-formed");
        }
        finally
        {
            SecurityDebugLogger.SetCurrentLogger(previousLogger);
        }

        await Task.CompletedTask; // keep async signature for fixture-friendly xUnit lifecycle
    }

    /// <summary>
    /// Builds a dummy OpenSecureChannelRequest body. The exact bytes don't matter for
    /// the decryption/verification test — only the length matters (it must be a plausible
    /// OPN body length so the padding calculation is exercised).
    ///
    /// Real OPN body = OpenSecureChannelRequest (OPC UA Part 4, 5.5.2):
    ///   RequestHeader + ClientProtocolVersion(UInt32) + RequestType(enum) + SecurityMode(enum) + ClientNonce(ByteString)
    /// A representative encoding is ~80-100 bytes.
    /// </summary>
    private static byte[] BuildDummyOpenSecureChannelRequestBody()
    {
        // Use BinaryEncoder to build a syntactically-valid OPN body.
        var enc = new BinaryEncoder();
        // RequestHeader
        enc.WriteByteString(null);             // AuthenticationToken (null ByteString = anonymous, pre-ActivateSession)
        enc.WriteString(null);                  // Timestamp (encoded as String? No — DateTime)
        enc.Reset();
        // Re-build properly. OPC UA RequestHeader is:
        //   AuthenticationToken(NodeId) + Timestamp(DateTime) + RequestHandle(UInt32) + ReturnDiagnostics(UInt32)
        //   + AuditEntryId(String) + TimeoutHint(UInt32) + AdditionalHeader(ExtensionObject)
        // For OPN (sent before ActivateSession), AuthenticationToken is null NodeId (encoding 0x00 0x00).
        enc.WriteUInt16(0);                     // NodeId encoding byte 0x00 + namespace 0x00 (two-byte form, id=0)
        enc.WriteUInt64(0);                     // Timestamp as Win32 FILETIME (UInt64) — DateTime in OPC UA binary
        enc.WriteUInt32(1);                     // RequestHandle
        enc.WriteUInt32(0);                     // ReturnDiagnostics
        enc.WriteString(null);                  // AuditEntryId
        enc.WriteUInt32(10000);                 // TimeoutHint
        enc.WriteByte(0);                       // AdditionalHeader encoding (no body)
        // OpenSecureChannelRequest body
        enc.WriteUInt32(0);                     // ClientProtocolVersion
        enc.WriteUInt32(0);                     // RequestType (Issue = 0)
        enc.WriteUInt32(3);                     // SecurityMode (SignAndEncrypt = 3)
        enc.WriteByteString(new byte[32]);      // ClientNonce (32 bytes)
        enc.WriteUInt32(3600000);               // RequestedLifetime
        return enc.ToByteArray();
    }

    private static string ToHex(byte[]? data, int maxBytes = int.MaxValue)
    {
        if (data == null) return "(null)";
        int len = Math.Min(data.Length, maxBytes);
        var sb = new StringBuilder(len * 3);
        for (int i = 0; i < len; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[i].ToString("X2"));
        }
        if (data.Length > maxBytes) sb.Append($" ... ({data.Length} bytes total)");
        return sb.ToString();
    }

    private static string ToHex(byte[] data, int offset, int count)
    {
        var sb = new StringBuilder(count * 3);
        for (int i = 0; i < count; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[offset + i].ToString("X2"));
        }
        return sb.ToString();
    }

    private static string ReadString(byte[] buf, ref int offset)
    {
        uint raw = BitConverter.ToUInt32(buf, offset);
        offset += 4;
        if (raw == 0xFFFFFFFF) return "";
        int len = (int)raw;
        string s = Encoding.UTF8.GetString(buf, offset, len);
        offset += len;
        return s;
    }

    private static byte[] ReadByteString(byte[] buf, ref int offset)
    {
        uint raw = BitConverter.ToUInt32(buf, offset);
        offset += 4;
        if (raw == 0xFFFFFFFF) return Array.Empty<byte>();
        int len = (int)raw;
        var bytes = new byte[len];
        Buffer.BlockCopy(buf, offset, bytes, 0, len);
        offset += len;
        return bytes;
    }
}
