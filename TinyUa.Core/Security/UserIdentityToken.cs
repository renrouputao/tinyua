using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TinyUa.Core.Security.Policies;

namespace TinyUa.Core.Security
{
    public enum UserTokenType
    {
        Anonymous = 0,
        UserName = 1,
        Certificate = 2,
        Issued = 3,
        Kerberos = 4
    }

    public class UserIdentityToken
    {
        public UserTokenType TokenType { get; set; }
        public string? PolicyId { get; set; }
        public byte[]? IssuedId { get; set; }
        public byte[]? SignatureData { get; set; }
        public string? Username { get; set; }
        public byte[]? Password { get; set; }
        public string? SecurityPolicyUri { get; set; }

        public string? EncryptionAlgorithm { get; set; }

        public static UserIdentityToken Anonymous()
        {
            return new UserIdentityToken
            {
                TokenType = UserTokenType.Anonymous,
                PolicyId = null,
                IssuedId = null,
                SignatureData = null
            };
        }

        public static UserIdentityToken CreateUserName(
            string username,
            string password,
            string? policyId = null,
            byte[]? serverNonce = null,
            byte[]? serverCertificate = null,
            string? securityPolicyUri = null)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var token = new UserIdentityToken
            {
                TokenType = UserTokenType.UserName,
                PolicyId = policyId,
                Username = username,
                Password = passwordBytes,
                SecurityPolicyUri = securityPolicyUri
            };

            if (serverNonce != null && serverCertificate != null
                && !string.IsNullOrEmpty(securityPolicyUri)
                && SecurityPolicyFactory.IsSecurePolicy(securityPolicyUri))
            {
                (token.Password, token.EncryptionAlgorithm) =
                    EncryptPassword(passwordBytes, serverNonce, serverCertificate, securityPolicyUri);
            }

            return token;
        }

        private static (byte[] encrypted, string algorithmUri) EncryptPassword(
            byte[] password, byte[] serverNonce, byte[] serverCertificate, string securityPolicyUri)
        {
            var plain = new byte[password.Length + serverNonce.Length];
            Buffer.BlockCopy(password, 0, plain, 0, password.Length);
            Buffer.BlockCopy(serverNonce, 0, plain, password.Length, serverNonce.Length);

            var lengthPrefixed = new byte[4 + plain.Length];
            lengthPrefixed[0] = (byte)(plain.Length & 0xFF);
            lengthPrefixed[1] = (byte)((plain.Length >> 8) & 0xFF);
            lengthPrefixed[2] = (byte)((plain.Length >> 16) & 0xFF);
            lengthPrefixed[3] = (byte)((plain.Length >> 24) & 0xFF);
            Buffer.BlockCopy(plain, 0, lengthPrefixed, 4, plain.Length);

            var cert = new X509Certificate2(serverCertificate);
            using var rsa = cert.GetRSAPublicKey()
                ?? throw new CryptographicException("Server certificate has no RSA public key.");

            RSAEncryptionPadding padding;
            string algorithmUri;
            if (securityPolicyUri.EndsWith("#Aes256_Sha256_RsaPss"))
            {
                padding = RSAEncryptionPadding.OaepSHA256;
                algorithmUri = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256";
            }
            else
            {
                padding = RSAEncryptionPadding.OaepSHA1;
                algorithmUri = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
            }

            int keySizeBytes = rsa.KeySize / 8;
            int oaepOverhead = padding == RSAEncryptionPadding.OaepSHA256 ? 66 : 42;
            int plainBlockSize = keySizeBytes - oaepOverhead;

            var cipher = new List<byte>(keySizeBytes);
            for (int offset = 0; offset < lengthPrefixed.Length; offset += plainBlockSize)
            {
                int len = Math.Min(plainBlockSize, lengthPrefixed.Length - offset);
                var block = new byte[len];
                Buffer.BlockCopy(lengthPrefixed, offset, block, 0, len);
                cipher.AddRange(rsa.Encrypt(block, padding));
            }

            return (cipher.ToArray(), algorithmUri);
        }
    }
}
