using System.Security.Cryptography;

namespace TinyUa.Core.Security.Cryptography
{
    internal sealed class RsaCryptography : ICryptography
    {
        private readonly RSA _localPrivateKey;
        private readonly RSA _remotePublicKey;
        private readonly RSAEncryptionPadding _encryptionPadding;
        private readonly HashAlgorithmName _signatureHash;
        private readonly RSASignaturePadding _signaturePadding;
        private readonly int _localKeySize;
        private readonly int _remoteKeySize;
        private readonly int _oaepOverhead;

        internal RsaCryptography(
            RSA localPrivateKey,
            RSA remotePublicKey,
            RSAEncryptionPadding encryptionPadding,
            HashAlgorithmName signatureHash,
            RSASignaturePadding signaturePadding,
            int oaepOverhead)
        {
            _localPrivateKey = localPrivateKey;
            _remotePublicKey = remotePublicKey;
            _encryptionPadding = encryptionPadding;
            _signatureHash = signatureHash;
            _signaturePadding = signaturePadding;
            _oaepOverhead = oaepOverhead;
            _localKeySize = localPrivateKey.KeySize / 8;
            _remoteKeySize = remotePublicKey.KeySize / 8;
        }

        public int PlainBlockSize => _remoteKeySize - _oaepOverhead;
        public int EncryptedBlockSize => _remoteKeySize;

        public int SignatureSize => _localKeySize;

        public int RemoteSignatureSize => _remoteKeySize;

        public int MinPaddingSize => 1;

        public byte[] Padding(int dataSize)
        {
            int extrapad = _remoteKeySize > 256 ? 2 : 1;
            int rem = (dataSize + SignatureSize + extrapad) % PlainBlockSize;
            if (rem != 0)
                rem = PlainBlockSize - rem;

            var padding = new byte[rem + extrapad];
            Array.Fill(padding, (byte)(rem & 0xFF));
            if (extrapad == 2)
                padding[^1] = (byte)((rem >> 8) & 0xFF);
            return padding;
        }

        public int GetPaddingSize(ReadOnlySpan<byte> data)
        {
            if (_localKeySize > 256)
            {
                if (data.Length < 2)
                    throw new CryptographicException("Invalid padding: data too short.");
                int padSize = (data[^2] | (data[^1] << 8)) + 2;
                if (padSize > data.Length)
                    throw new CryptographicException($"Invalid padding length {padSize} for {data.Length} bytes.");
                return padSize;
            }
            if (data.Length < 1)
                throw new CryptographicException("Invalid padding: data too short.");
            int pad = data[^1] + 1;
            if (pad > data.Length)
                throw new CryptographicException($"Invalid padding length {pad} for {data.Length} bytes.");
            return pad;
        }

        public byte[] Encrypt(byte[] data)
        {
            int plainBlock = PlainBlockSize;
            if (data.Length <= plainBlock)
                return _remotePublicKey.Encrypt(data, _encryptionPadding);

            int blockCount = (data.Length + plainBlock - 1) / plainBlock;
            var result = new byte[blockCount * _remoteKeySize];
            var block = new byte[plainBlock];
            for (int i = 0; i < blockCount; i++)
            {
                int off = i * plainBlock;
                int len = Math.Min(plainBlock, data.Length - off);
                Buffer.BlockCopy(data, off, block, 0, len);
                var enc = len == plainBlock
                    ? _remotePublicKey.Encrypt(block, _encryptionPadding)
                    : _remotePublicKey.Encrypt(block.AsSpan(0, len).ToArray(), _encryptionPadding);
                Buffer.BlockCopy(enc, 0, result, i * _remoteKeySize, _remoteKeySize);
            }
            return result;
        }

        public bool TryEncryptInPlace(byte[] data) => false;

        public byte[] Decrypt(ReadOnlySpan<byte> data)
        {
            if (data.Length == _localKeySize)
                return _localPrivateKey.Decrypt(data, _encryptionPadding);

            if (data.Length % _localKeySize != 0)
                throw new CryptographicException(
                    $"Ciphertext length ({data.Length}) is not a multiple of the key size ({_localKeySize}) — truncated or forged data");

            int blockCount = data.Length / _localKeySize;
            using var ms = new System.IO.MemoryStream(blockCount * (_localKeySize - _oaepOverhead));
            for (int i = 0; i < blockCount; i++)
            {
                var dec = _localPrivateKey.Decrypt(data.Slice(i * _localKeySize, _localKeySize), _encryptionPadding);
                ms.Write(dec, 0, dec.Length);
            }
            return ms.ToArray();
        }

        public byte[] Sign(byte[] data)
            => _localPrivateKey.SignData(data, _signatureHash, _signaturePadding);

        public byte[] Sign(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader, ReadOnlySpan<byte> body)
        {
            using var hash = IncrementalHash.CreateHash(_signatureHash);
            hash.AppendData(header);
            hash.AppendData(securityHeader);
            hash.AppendData(body);
            Span<byte> digest = stackalloc byte[64];
            var digestLength = hash.GetHashAndReset(digest);
            var signature = new byte[SignatureSize];
            if (!_localPrivateKey.TrySignHash(digest[..digestLength], signature, _signatureHash, _signaturePadding, out var written))
                throw new CryptographicException("RSA signature destination was unexpectedly too small.");
            return written == signature.Length ? signature : signature[..written];
        }

        public bool VerifyData(byte[] data, ReadOnlySpan<byte> signature)
            => _remotePublicKey.VerifyData(data, signature, _signatureHash, _signaturePadding);

        public void Verify(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader,
            ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature)
        {
            // Asymmetric verify runs once per handshake — materializing the signed data here
            // is not a hot-path concern.
            var data = new byte[header.Length + securityHeader.Length + body.Length];
            header.CopyTo(data);
            securityHeader.CopyTo(data.AsSpan(header.Length));
            body.CopyTo(data.AsSpan(header.Length + securityHeader.Length));
            if (!_remotePublicKey.VerifyData(data, signature, _signatureHash, _signaturePadding))
                throw new CryptographicException("Asymmetric signature verification failed.");
        }
    }
}
