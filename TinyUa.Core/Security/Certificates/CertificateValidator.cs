using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TinyUa.Core.Security.Certificates
{
    internal enum CertificateValidationMode
    {
        None = 0,

        Basic = 1
    }

    internal sealed class CertificateValidator
    {
        internal CertificateValidationMode Mode { get; set; } = CertificateValidationMode.Basic;

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
