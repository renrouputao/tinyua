using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TinyUa.Core.Security.Policies;

namespace TinyUa.Core.Security
{
    /// <summary>
    /// Enumerates the OPC UA user identity token types supported for session authentication.
    /// </summary>
    public enum UserTokenType
    {
        /// <summary>Anonymous login (no credentials).</summary>
        Anonymous = 0,
        /// <summary>Username and password authentication.</summary>
        UserName = 1,
        /// <summary>X.509 certificate-based authentication.</summary>
        Certificate = 2,
        /// <summary>Issued token (e.g. WS-Trust).</summary>
        Issued = 3,
        /// <summary>Kerberos ticket.</summary>
        Kerberos = 4
    }

    /// <summary>
    /// Represents an OPC UA user identity token used to authenticate a session.
    /// Supports anonymous and username/password tokens with optional encryption.
    /// </summary>
    public class UserIdentityToken
    {
        /// <summary>
        /// Gets or sets the type of user identity token.
        /// </summary>
        public UserTokenType TokenType { get; set; }

        /// <summary>
        /// Gets or sets the policy ID for the selected user token policy from the server's endpoint.
        /// </summary>
        public string? PolicyId { get; set; }

        /// <summary>
        /// Gets or sets the issued token data (used for Issued token type).
        /// </summary>
        public byte[]? IssuedId { get; set; }

        /// <summary>
        /// Gets or sets the signature data for the token.
        /// </summary>
        public byte[]? SignatureData { get; set; }

        /// <summary>
        /// Gets or sets the username for UserName token type.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Gets or sets the password bytes for UserName token type.
        /// May be encrypted depending on security configuration.
        /// </summary>
        public byte[]? Password { get; set; }

        /// <summary>
        /// Gets or sets the security policy URI used for password encryption.
        /// </summary>
        public string? SecurityPolicyUri { get; set; }

        /// <summary>
        /// Gets or sets the encryption algorithm URI used when the password was encrypted.
        /// </summary>
        public string? EncryptionAlgorithm { get; set; }

        /// <summary>
        /// Creates an anonymous user identity token.
        /// </summary>
        /// <returns>A new <see cref="UserIdentityToken"/> configured for anonymous authentication.</returns>
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

        /// <summary>
        /// Creates a username/password user identity token, optionally encrypting the password
        /// using the server certificate and nonce when a secure policy is specified.
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="password">The plain-text password.</param>
        /// <param name="policyId">Optional policy ID from the server endpoint.</param>
        /// <param name="serverNonce">Optional server nonce for encryption.</param>
        /// <param name="serverCertificate">Optional server certificate for RSA encryption.</param>
        /// <param name="securityPolicyUri">Optional security policy URI. When provided with a secure policy, the password is encrypted.</param>
        /// <returns>A new <see cref="UserIdentityToken"/> configured for username authentication.</returns>
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

        /// <summary>
        /// Encrypts a password using the server's public RSA key from its certificate.
        /// The plaintext is the concatenation of password + server nonce, length-prefixed.
        /// </summary>
        /// <param name="password">The password bytes.</param>
        /// <param name="serverNonce">The server nonce.</param>
        /// <param name="serverCertificate">The DER-encoded X.509 server certificate.</param>
        /// <param name="securityPolicyUri">The security policy URI (determines OAEP hash).</param>
        /// <returns>A tuple containing the encrypted bytes and the algorithm URI.</returns>
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
