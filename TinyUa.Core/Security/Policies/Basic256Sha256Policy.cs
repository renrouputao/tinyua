using System.Security.Cryptography;
using TinyUa.Core.Security.Cryptography;

namespace TinyUa.Core.Security.Policies
{
    internal sealed class Basic256Sha256Policy : SecurityPolicyBase
    {
        public override string Uri => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

        public override int SymmetricKeySize => 32;

        protected override RsaCryptography CreateAsymmetricCryptography(RSA localPrivate, RSA remotePublic)
            => new RsaCryptography(
                localPrivate,
                remotePublic,
                RSAEncryptionPadding.OaepSHA1,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1,
                oaepOverhead: 42);
    }
}
