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
        void Verify(byte[] data, byte[] signature);
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        byte[] RemovePadding(byte[] data);
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
        public void Verify(byte[] data, byte[] signature) { }
        public byte[] Encrypt(byte[] data) => data;
        public byte[] Decrypt(byte[] data) => data;
        public byte[] RemovePadding(byte[] data) => data;
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
