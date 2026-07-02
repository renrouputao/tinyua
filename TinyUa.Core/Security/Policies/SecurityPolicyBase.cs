using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Security.Cryptography;

namespace TinyUa.Core.Security.Policies
{
    internal abstract class SecurityPolicyBase : SecurityPolicy
    {
        private RsaCryptography? _asymmetric;
        private AesCryptography? _symmetric;
        private int _asymmetricSignatureSize;

        protected X509Certificate2? LocalCertificate;
        protected X509Certificate2? RemoteCertificate;

        public override int SignatureKeySize => 32;
        public override int SymmetricSignatureSize => 32;
        public override int AsymmetricSignatureSize => _asymmetricSignatureSize;

        public override ICryptography AsymmetricCryptography =>
            _asymmetric ?? throw new InvalidOperationException(
                "Security policy not initialized. Call Initialize() before use.");

        public override ICryptography SymmetricCryptography =>
            _symmetric ?? throw new InvalidOperationException(
                "Security policy not initialized. Call Initialize() before use.");

        public override int NonceLength => 32;

        public override void MakeLocalSymmetricKey(byte[]? secret, byte[]? seed)
            => _symmetric?.MakeLocalKeys(secret, seed);

        public override void MakeRemoteSymmetricKey(byte[]? secret, byte[]? seed)
            => _symmetric?.MakeRemoteKeys(secret, seed);

        internal void Initialize(
            X509Certificate2? localCert,
            X509Certificate2? remoteCert,
            MessageSecurityMode mode)
        {
            if (mode != MessageSecurityMode.Sign && mode != MessageSecurityMode.SignAndEncrypt)
                throw new ArgumentException(
                    "Security mode must be Sign or SignAndEncrypt for a secure policy.", nameof(mode));

            ArgumentNullException.ThrowIfNull(localCert);
            ArgumentNullException.ThrowIfNull(remoteCert);

            LocalCertificate = localCert;
            RemoteCertificate = remoteCert;
            SecurityMode = mode;

            SenderCertificate = localCert.Export(X509ContentType.Cert);

            using var sha1 = SHA1.Create();
            ReceiverThumbprint = sha1.ComputeHash(remoteCert.RawData);

            var localPrivate = localCert.GetRSAPrivateKey()
                ?? throw new CryptographicException(
                    "Local certificate does not contain an RSA private key.");
            var remotePublic = remoteCert.GetRSAPublicKey()
                ?? throw new CryptographicException(
                    "Remote certificate does not contain an RSA public key.");

            _asymmetricSignatureSize = localPrivate.KeySize / 8;

            _asymmetric = CreateAsymmetricCryptography(localPrivate, remotePublic);

            _symmetric = new AesCryptography(SignatureKeySize, SymmetricKeySize, 16, mode);
        }

        protected abstract RsaCryptography CreateAsymmetricCryptography(RSA localPrivate, RSA remotePublic);
    }
}
