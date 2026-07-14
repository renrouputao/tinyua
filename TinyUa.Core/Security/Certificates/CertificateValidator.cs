using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TinyUa.Core.Security.Certificates
{
    internal enum CertificateValidationMode
    {
        None = 0,

        Basic = 1,

        /// <summary>
        /// Extends <see cref="Basic"/> with X509 chain building. Validates that intermediate
        /// certificates are cryptographically consistent (no forged intermediates) and that all
        /// certs in the chain are within their validity period. Unknown root authorities are
        /// allowed (common in OPC UA, which uses custom CAs). CRL revocation is not checked.
        /// </summary>
        Standard = 2
    }

    internal sealed class CertificateValidator
    {
        internal CertificateValidationMode Mode { get; set; } = CertificateValidationMode.Standard;

        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
        private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

        internal void Validate(X509Certificate2? certificate, bool isServerCertificate)
        {
            if (Mode == CertificateValidationMode.None)
                return;

            if (certificate == null)
                throw new CryptographicException("A certificate is required but none was provided.");

            var now = DateTimeOffset.UtcNow;
            if (now < certificate.NotBefore)
                throw new CryptographicException(
                    $"Certificate is not yet valid (not before {certificate.NotBefore:O}).");

            if (now > certificate.NotAfter)
                throw new CryptographicException(
                    $"Certificate has expired (not after {certificate.NotAfter:O}).");

            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku != null)
            {
                var requiredOid = isServerCertificate ? ServerAuthOid : ClientAuthOid;
                bool hasRequiredUsage = false;
                foreach (var oid in eku.EnhancedKeyUsages)
                {
                    if (oid.Value == requiredOid || oid.Value == null)
                    {
                        hasRequiredUsage = true;
                        break;
                    }
                }
                if (!hasRequiredUsage)
                    throw new CryptographicException(
                        $"Certificate is missing the required ExtendedKeyUsage '{requiredOid}'.");
            }

            if (Mode == CertificateValidationMode.Standard)
                ValidateChain(certificate);
        }

        /// <summary>
        /// Builds an X509 chain and rejects certs with structural/signature errors. Unknown root
        /// authorities are allowed (OPC UA uses custom CAs) and CRL is not checked — this catches
        /// forged intermediates and expired chain elements, not untrusted roots. Full trust-store
        /// integration is a future enhancement.
        /// </summary>
        private static void ValidateChain(X509Certificate2 certificate)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            // Ignore the "no build error" that occurs when a self-signed cert's root is not trusted —
            // AllowUnknownCertificateAuthority covers UntrustedRoot, but partial-chain errors from
            // missing intermediates should still surface.
            if (!chain.Build(certificate))
            {
                // Filter out benign status flags that are expected for OPC UA self-signed / custom-CA certs
                for (int i = 0; i < chain.ChainStatus.Length; i++)
                {
                    var flag = chain.ChainStatus[i].Status;
                    if (flag == X509ChainStatusFlags.UntrustedRoot
                        || flag == X509ChainStatusFlags.NoError)
                        continue;

                    throw new CryptographicException(
                        $"Certificate chain validation failed: {flag} — {chain.ChainStatus[i].StatusInformation}");
                }
            }
        }

        internal bool IsValid(X509Certificate2? certificate, bool isServerCertificate)
        {
            try
            {
                Validate(certificate, isServerCertificate);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
