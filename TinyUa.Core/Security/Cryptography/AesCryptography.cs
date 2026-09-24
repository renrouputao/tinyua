using System.Security.Cryptography;
using TinyUa.Core.Logging;

namespace TinyUa.Core.Security.Cryptography
{
    internal sealed class AesCryptography : ICryptography, IDisposable
    {
        private readonly int _signatureKeySize;
        private readonly int _encryptionKeySize;
        private readonly int _blockSize;
        private readonly bool _isEncrypted;

        private byte[]? _localSigKey;
        private byte[]? _remoteSigKey;
        private byte[]? _localSigKeyRetired;
        private byte[]? _remoteSigKeyRetired;

        public void Dispose()
        {
            _localCipher?.Dispose();
            _remoteCipher?.Dispose();
            _localCipherRetired?.Dispose();
            _remoteCipherRetired?.Dispose();
            if (_localSigKey != null) CryptographicOperations.ZeroMemory(_localSigKey);
            if (_remoteSigKey != null) CryptographicOperations.ZeroMemory(_remoteSigKey);
            if (_localSigKeyRetired != null) CryptographicOperations.ZeroMemory(_localSigKeyRetired);
            if (_remoteSigKeyRetired != null) CryptographicOperations.ZeroMemory(_remoteSigKeyRetired);
        }

        // (Aes, IV) pairs are swapped as one reference on rekey so a concurrent one-shot
        // Encrypt/Decrypt never observes a new key paired with an old IV. The previous instance
        // is retired (disposed) on the NEXT rekey rather than immediately, giving any in-flight
        // operation a full token lifetime to complete.
        private volatile CipherState? _localCipher;
        private volatile CipherState? _remoteCipher;
        private CipherState? _localCipherRetired;
        private CipherState? _remoteCipherRetired;

        private sealed class CipherState : IDisposable
        {
            internal readonly Aes Aes;
            internal readonly byte[] Iv;

            internal CipherState(byte[] key, byte[] iv)
            {
                Aes = Aes.Create();
                Aes.Key = key;
                Iv = iv;
            }

            public void Dispose() { Aes.Dispose(); CryptographicOperations.ZeroMemory(Iv); }
        }

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
            if (_localSigKeyRetired != null) CryptographicOperations.ZeroMemory(_localSigKeyRetired);
            _localSigKeyRetired = _localSigKey;
            _localSigKey = derived[.._signatureKeySize];
            var encKey = derived[_signatureKeySize..(_signatureKeySize + _encryptionKeySize)];
            var iv = derived[(_signatureKeySize + _encryptionKeySize)..];

            if (_isEncrypted)
            {
                _localCipherRetired?.Dispose();
                _localCipherRetired = _localCipher;
                _localCipher = new CipherState(encKey, iv);
            }

            SecurityDebugLogger.LogStage("AesCryptography.MakeLocalKeys",
                ("secretLen", secret?.Length ?? -1),
                ("seedLen", seed?.Length ?? -1),
                ("isEncrypted", _isEncrypted));
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(encKey);
        }

        internal void MakeRemoteKeys(byte[]? secret, byte[]? seed)
        {
            int total = _signatureKeySize + _encryptionKeySize + _blockSize;
            var derived = PSha256.Derive(secret!, seed!, total);
            if (_remoteSigKeyRetired != null) CryptographicOperations.ZeroMemory(_remoteSigKeyRetired);
            _remoteSigKeyRetired = _remoteSigKey;
            _remoteSigKey = derived[.._signatureKeySize];
            var encKey = derived[_signatureKeySize..(_signatureKeySize + _encryptionKeySize)];
            var iv = derived[(_signatureKeySize + _encryptionKeySize)..];

            if (_isEncrypted)
            {
                _remoteCipherRetired?.Dispose();
                _remoteCipherRetired = _remoteCipher;
                _remoteCipher = new CipherState(encKey, iv);
            }

            SecurityDebugLogger.LogStage("AesCryptography.MakeRemoteKeys",
                ("secretLen", secret?.Length ?? -1),
                ("seedLen", seed?.Length ?? -1),
                ("isEncrypted", _isEncrypted));
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(encKey);
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

        public int GetPaddingSize(ReadOnlySpan<byte> data)
        {
            if (!_isEncrypted)
                return 0;

            if (_blockSize > 256)
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

        public byte[] Sign(byte[] data)
            => HMACSHA256.HashData(_localSigKey!, data);

        public byte[] Sign(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader, ReadOnlySpan<byte> body)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _localSigKey!);
            hmac.AppendData(header);
            hmac.AppendData(securityHeader);
            hmac.AppendData(body);
            var signature = new byte[SignatureSize];
            hmac.GetHashAndReset(signature);
            return signature;
        }

        public bool VerifyData(byte[] data, ReadOnlySpan<byte> signature)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _remoteSigKey!);
            hmac.AppendData(data);
            Span<byte> expected = stackalloc byte[32];
            hmac.GetHashAndReset(expected);
            return CryptographicOperations.FixedTimeEquals(expected, signature);
        }

        public void Verify(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader,
            ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _remoteSigKey!);
            hmac.AppendData(header);
            hmac.AppendData(securityHeader);
            hmac.AppendData(body);
            Span<byte> expected = stackalloc byte[32];
            hmac.GetHashAndReset(expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, signature))
                throw new CryptographicException("Symmetric signature verification failed.");
        }

        public byte[] Encrypt(byte[] data)
        {
            if (!_isEncrypted)
                return data;

            var cipher = _localCipher
                ?? throw new CryptographicException("Local symmetric key not initialized.");
            return cipher.Aes.EncryptCbc(data, cipher.Iv, PaddingMode.None);
        }

        public bool TryEncryptInPlace(byte[] data)
            => TryEncryptInPlace(data.AsSpan());

        public bool TryEncryptInPlace(Span<byte> data)
        {
            if (!_isEncrypted)
                return true;

            var cipher = _localCipher
                ?? throw new CryptographicException("Local symmetric key not initialized.");
            return cipher.Aes.TryEncryptCbc(data, cipher.Iv, data, out var written, PaddingMode.None)
                && written == data.Length;
        }

        public byte[] Decrypt(ReadOnlySpan<byte> data)
        {
            if (!_isEncrypted)
                return data.ToArray();

            var cipher = _remoteCipher
                ?? throw new CryptographicException("Remote symmetric key not initialized.");
            return cipher.Aes.DecryptCbc(data, cipher.Iv, PaddingMode.None);
        }
    }
}
