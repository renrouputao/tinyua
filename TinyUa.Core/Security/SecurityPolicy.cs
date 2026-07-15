using System;

namespace TinyUa.Core.Security
{
    /// <summary>
    /// Specifies the OPC UA message security mode for a secure channel.
    /// </summary>
    public enum MessageSecurityMode
    {
        /// <summary>An invalid or unspecified security mode.</summary>
        Invalid = 0,
        /// <summary>Messages are sent without any cryptographic protection.</summary>
        None = 1,
        /// <summary>Messages are signed but not encrypted.</summary>
        Sign = 2,
        /// <summary>Messages are signed and encrypted.</summary>
        SignAndEncrypt = 3
    }

    internal abstract class SecurityPolicy
    {
        public abstract string Uri { get; }
        public abstract int SignatureKeySize { get; }
        public abstract int SymmetricKeySize { get; }
        public abstract int AsymmetricSignatureSize { get; }
        public abstract int SymmetricSignatureSize { get; }

        public MessageSecurityMode SecurityMode { get; protected set; }

        public byte[]? SenderCertificate { get; protected set; }

        public byte[]? ReceiverThumbprint { get; protected set; }

        public virtual int NonceLength => 0;

        public abstract ICryptography AsymmetricCryptography { get; }
        public abstract ICryptography SymmetricCryptography { get; }

        public abstract void MakeLocalSymmetricKey(byte[]? secret, byte[]? seed);
        public abstract void MakeRemoteSymmetricKey(byte[]? secret, byte[]? seed);
    }

    internal interface ICryptography
    {
        int PlainBlockSize { get; }
        int EncryptedBlockSize { get; }
        int SignatureSize { get; }
        int RemoteSignatureSize { get; }
        int MinPaddingSize { get; }

        byte[] Padding(int dataSize);
        byte[] Sign(byte[] data);

        /// <summary>Signs three protocol segments without materializing their concatenation.</summary>
        byte[] Sign(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader, ReadOnlySpan<byte> body);

        /// <summary>
        /// Verifies a signature over arbitrary data using the remote party's public key.
        /// Used for CreateSession ServerSignature verification (OPC UA Part 4 §5.6.2).
        /// Returns true if the signature is valid, false otherwise. None-policy implementations
        /// return true (no signature to verify).
        /// </summary>
        bool VerifyData(byte[] data, ReadOnlySpan<byte> signature);

        /// <summary>
        /// Verifies the remote signature computed over the concatenation
        /// header | securityHeader | body, without requiring the caller to materialize it.
        /// </summary>
        void Verify(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader,
            ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature);

        byte[] Encrypt(byte[] data);

        /// <summary>Attempts to encrypt a complete protocol payload in place.</summary>
        bool TryEncryptInPlace(byte[] data);
        byte[] Decrypt(ReadOnlySpan<byte> data);

        /// <summary>
        /// Returns the number of trailing padding bytes (including the padding-size field) in the
        /// decrypted plaintext, or 0 when the mode does not add padding. Callers slice the
        /// plaintext instead of allocating an unpadded copy.
        /// </summary>
        int GetPaddingSize(ReadOnlySpan<byte> data);
    }

    internal class NoneCryptography : ICryptography
    {
        public int PlainBlockSize => 1;
        public int EncryptedBlockSize => 1;
        public int SignatureSize => 0;
        public int RemoteSignatureSize => 0;
        public int MinPaddingSize => 0;

        public byte[] Padding(int dataSize) => Array.Empty<byte>();
        public byte[] Sign(byte[] data) => Array.Empty<byte>();
        public byte[] Sign(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader, ReadOnlySpan<byte> body) => Array.Empty<byte>();
        public bool VerifyData(byte[] data, ReadOnlySpan<byte> signature) => true;
        public void Verify(ReadOnlySpan<byte> header, ReadOnlySpan<byte> securityHeader,
            ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature) { }
        public byte[] Encrypt(byte[] data) => data;
        public bool TryEncryptInPlace(byte[] data) => true;
        public byte[] Decrypt(ReadOnlySpan<byte> data) => data.ToArray();
        public int GetPaddingSize(ReadOnlySpan<byte> data) => 0;
    }

    internal class NoneSecurityPolicy : SecurityPolicy
    {
        private readonly NoneCryptography _cryptography = new NoneCryptography();

        private const string NoneUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
        public override string Uri => NoneUri;
        public override int SignatureKeySize => 0;
        public override int SymmetricKeySize => 0;
        public override int AsymmetricSignatureSize => 0;
        public override int SymmetricSignatureSize => 0;

        public override ICryptography AsymmetricCryptography => _cryptography;
        public override ICryptography SymmetricCryptography => _cryptography;

        internal NoneSecurityPolicy()
        {
            SecurityMode = MessageSecurityMode.None;
        }

        public override void MakeLocalSymmetricKey(byte[]? secret, byte[]? seed) { }
        public override void MakeRemoteSymmetricKey(byte[]? secret, byte[]? seed) { }
    }
}
