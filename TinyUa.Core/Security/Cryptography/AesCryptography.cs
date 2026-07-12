using System.Security.Cryptography;
using TinyUa.Core.Logging;

namespace TinyUa.Core.Security.Cryptography
{
    internal sealed class AesCryptography : ICryptography
    {
        private readonly int _signatureKeySize;
        private readonly int _encryptionKeySize;
        private readonly int _blockSize;
        private readonly bool _isEncrypted;

        private byte[]? _localSigKey;
        private byte[]? _localEncKey;
        private byte[]? _localIv;

        private byte[]? _remoteSigKey;
        private byte[]? _remoteEncKey;
        private byte[]? _remoteIv;

        internal AesCryptography(int signatureKeySize, int encryptionKeySize, int blockSize, MessageSecurityMode mode)
        {
            _signatureKeySize = signatureKeySize;
            _encryptionKeySize = encryptionKeySize;
            _blockSize = blockSize;
            _isEncrypted = mode == MessageSecurityMode.SignAndEncrypt;
        }

        public int PlainBlockSize => _isEncrypted ? _blockSize : 1;
        public int EncryptedBlockSize => _isEncrypted ? _blockSize : 1;
        public int SignatureSize => _signatureKeySize;
        public int RemoteSignatureSize => _signatureKeySize;
        public int MinPaddingSize => _isEncrypted ? 1 : 0;

        internal void MakeLocalKeys(byte[]? secret, byte[]? seed)
        {
            int total = _signatureKeySize + _encryptionKeySize + _blockSize;
            var derived = PSha256.Derive(secret!, seed!, total);
            _localSigKey = derived[.._signatureKeySize];
            _localEncKey = derived[_signatureKeySize..(_signatureKeySize + _encryptionKeySize)];
            _localIv = derived[(_signatureKeySize + _encryptionKeySize)..];

            SecurityDebugLogger.LogStage("AesCryptography.MakeLocalKeys",
                ("secretLen", secret?.Length ?? -1),
                ("seedLen", seed?.Length ?? -1),
                ("sigKeyPrefix", Hex8(_localSigKey)),
                ("encKeyPrefix", Hex8(_localEncKey)),
                ("ivPrefix", Hex8(_localIv)),
                ("isEncrypted", _isEncrypted));
        }

        internal void MakeRemoteKeys(byte[]? secret, byte[]? seed)
        {
            int total = _signatureKeySize + _encryptionKeySize + _blockSize;
            var derived = PSha256.Derive(secret!, seed!, total);
            _remoteSigKey = derived[.._signatureKeySize];
            _remoteEncKey = derived[_signatureKeySize..(_signatureKeySize + _encryptionKeySize)];
            _remoteIv = derived[(_signatureKeySize + _encryptionKeySize)..];

            SecurityDebugLogger.LogStage("AesCryptography.MakeRemoteKeys",
                ("secretLen", secret?.Length ?? -1),
                ("seedLen", seed?.Length ?? -1),
                ("sigKeyPrefix", Hex8(_remoteSigKey)),
                ("encKeyPrefix", Hex8(_remoteEncKey)),
                ("ivPrefix", Hex8(_remoteIv)),
                ("isEncrypted", _isEncrypted));
        }

        private static string Hex8(byte[]? key)
        {
            if (key == null || key.Length == 0) return "(null)";
            int len = System.Math.Min(8, key.Length);
            var hex = new System.Text.StringBuilder(len * 2);
            for (int i = 0; i < len; i++) hex.Append(key[i].ToString("X2"));
            return hex.ToString();
        }

        public byte[] Padding(int dataSize)
        {
            if (!_isEncrypted)
                return Array.Empty<byte>();

            int extrapad = _blockSize > 256 ? 2 : 1;
            int rem = (dataSize + SignatureSize + extrapad) % _blockSize;
            if (rem != 0)
                rem = _blockSize - rem;

            var padding = new byte[rem + extrapad];
            Array.Fill(padding, (byte)(rem & 0xFF));
            if (extrapad == 2)
                padding[^1] = (byte)((rem >> 8) & 0xFF);
            return padding;
        }

        public byte[] RemovePadding(byte[] data)
        {
            if (!_isEncrypted)
                return data;

            if (_blockSize > 256)
            {
                if (data.Length < 2)
                    throw new CryptographicException("Invalid padding: data too short.");
                int padSize = (data[^2] | (data[^1] << 8)) + 2;
                if (padSize > data.Length)
                    throw new CryptographicException($"Invalid padding length {padSize} for {data.Length} bytes.");
                return data[..^padSize];
            }
            if (data.Length < 1)
                throw new CryptographicException("Invalid padding: data too short.");
            int pad = data[^1] + 1;
            if (pad > data.Length)
                throw new CryptographicException($"Invalid padding length {pad} for {data.Length} bytes.");
            return data[..^pad];
        }

        public byte[] Sign(byte[] data)
            => HMACSHA256.HashData(_localSigKey!, data);

        public void Verify(byte[] data, byte[] signature)
        {
            var expected = HMACSHA256.HashData(_remoteSigKey!, data);
            if (!CryptographicOperations.FixedTimeEquals(expected, signature))
                throw new CryptographicException("Symmetric signature verification failed.");
        }

        public byte[] Encrypt(byte[] data)
        {
            if (!_isEncrypted)
                return data;

            using var aes = Aes.Create();
            aes.Key = _localEncKey!;
            aes.IV = _localIv!;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(data, 0, data.Length);
        }

        public byte[] Decrypt(byte[] data)
        {
            if (!_isEncrypted)
                return data;

            using var aes = Aes.Create();
            aes.Key = _remoteEncKey!;
            aes.IV = _remoteIv!;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
