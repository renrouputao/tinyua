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

        public byte[] RemovePadding(byte[] data)
        {
            if (_localKeySize > 256)
            {
                int padSize = (data[^2] | (data[^1] << 8)) + 2;
                return data[..^padSize];
            }
            int pad = data[^1] + 1;
            return data[..^pad];
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

        public byte[] Decrypt(byte[] data)
        {
            if (data.Length == _localKeySize)
                return _localPrivateKey.Decrypt(data, _encryptionPadding);

            int blockCount = data.Length / _localKeySize;
            using var ms = new System.IO.MemoryStream(blockCount * (_localKeySize - _oaepOverhead));
            var block = new byte[_localKeySize];
            for (int i = 0; i < blockCount; i++)
            {
                Buffer.BlockCopy(data, i * _localKeySize, block, 0, _localKeySize);
                var dec = _localPrivateKey.Decrypt(block, _encryptionPadding);
                ms.Write(dec, 0, dec.Length);
            }
            return ms.ToArray();
        }

        public byte[] Sign(byte[] data)
            => _localPrivateKey.SignData(data, _signatureHash, _signaturePadding);

        public void Verify(byte[] data, byte[] signature)
        {
            if (!_remotePublicKey.VerifyData(data, signature, _signatureHash, _signaturePadding))
                throw new CryptographicException("Asymmetric signature verification failed.");
        }
    }
}
