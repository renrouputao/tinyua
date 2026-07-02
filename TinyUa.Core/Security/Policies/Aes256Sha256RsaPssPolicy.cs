using System.Security.Cryptography;
using TinyUa.Core.Security.Cryptography;

namespace TinyUa.Core.Security.Policies
{
    internal sealed class Aes256Sha256RsaPssPolicy : SecurityPolicyBase
    {
        public override string Uri => "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

        public override int SymmetricKeySize => 32;

        protected override RsaCryptography CreateAsymmetricCryptography(RSA localPrivate, RSA remotePublic)
            => new RsaCryptography(
                localPrivate,
                remotePublic,
                RSAEncryptionPadding.OaepSHA256,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss,
                oaepOverhead: 66);
    }
}
