using System.Security.Cryptography;
using TinyUa.Core.Security.Cryptography;

namespace TinyUa.Core.Security.Policies
{
    internal sealed class Aes128Sha256RsaOaepPolicy : SecurityPolicyBase
    {
        public override string Uri => "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";

        public override int SymmetricKeySize => 16;

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
