using System;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Logging;
using TinyUa.Core.Security.Policies;

namespace TinyUa.Core.Security
{
    internal static class SecurityPolicyFactory
    {
        private const string PolicyUriPrefix = "http://opcfoundation.org/UA/SecurityPolicy#";

        internal static string NormalizePolicyUri(string policy)
        {
            if (string.IsNullOrEmpty(policy))
                return PolicyUriPrefix + "None";

            if (policy.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                return policy;

            return PolicyUriPrefix + policy;
        }

        internal static SecurityPolicy Create(
            string policyUri,
            X509Certificate2? localCert,
            X509Certificate2? remoteCert,
            MessageSecurityMode mode)
        {
            var uri = NormalizePolicyUri(policyUri);

            if (uri == PolicyUriPrefix + "None")
            {
                SecurityDebugLogger.LogStage("SecurityPolicyFactory.Create",
                    ("policyUri", uri),
                    ("mode", mode),
                    ("result", "NoneSecurityPolicy"));
                return new NoneSecurityPolicy();
            }

            if (mode != MessageSecurityMode.Sign && mode != MessageSecurityMode.SignAndEncrypt)
                throw new ArgumentException(
                    $"Security mode must be Sign or SignAndEncrypt for policy '{policyUri}', " +
                    $"but was {mode}.", nameof(mode));

            SecurityPolicyBase policy = uri switch
            {
                var u when u == PolicyUriPrefix + "Basic256Sha256" => new Basic256Sha256Policy(),
                var u when u == PolicyUriPrefix + "Aes128_Sha256_RsaOaep" => new Aes128Sha256RsaOaepPolicy(),
                var u when u == PolicyUriPrefix + "Aes256_Sha256_RsaPss" => new Aes256Sha256RsaPssPolicy(),
                _ => throw new ArgumentException($"Unsupported security policy: '{policyUri}'", nameof(policyUri))
            };

            policy.Initialize(localCert, remoteCert, mode);

            SecurityDebugLogger.LogStage("SecurityPolicyFactory.Create",
                ("policyUri", uri),
                ("mode", mode),
                ("localCertThumbprint", localCert?.Thumbprint),
                ("remoteCertThumbprint", remoteCert?.Thumbprint),
                ("symKeySize", policy.SymmetricKeySize),
                ("asymSigSize", policy.AsymmetricSignatureSize),
                ("nonceLength", policy.NonceLength));

            return policy;
        }

        internal static bool IsSecurePolicy(string policyUri)
        {
            var uri = NormalizePolicyUri(policyUri);
            return uri != PolicyUriPrefix + "None";
        }
    }
}
