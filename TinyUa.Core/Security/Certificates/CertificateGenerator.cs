using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TinyUa.Core.Security.Certificates
{
    internal static class CertificateGenerator
    {
        internal static (X509Certificate2 Certificate, RSA PrivateKey) CreateSelfSigned(
            string applicationName,
            string applicationUri,
            int keySize = 2048,
            int validityYears = 5)
        {
            var rsa = RSA.Create(keySize);

            var req = new CertificateRequest(
                $"CN={applicationName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddUri(new Uri(applicationUri));
            string hostName;
            try { hostName = Environment.MachineName; }
            catch { hostName = "localhost"; }
            sanBuilder.AddDnsName(hostName);
            req.CertificateExtensions.Add(sanBuilder.Build());

            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));

            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.KeyEncipherment
                    | X509KeyUsageFlags.DataEncipherment
                    | X509KeyUsageFlags.NonRepudiation,
                    true));

            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new Oid("1.3.6.1.5.5.7.3.2"),
                        new Oid("1.3.6.1.5.5.7.3.1")
                    },
                    true));

            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var notAfter = DateTimeOffset.UtcNow.AddYears(validityYears);

            var ephemeral = req.CreateSelfSigned(notBefore, notAfter);
            byte[] pfx = ephemeral.Export(X509ContentType.Pfx);
            ephemeral.Dispose();

            X509Certificate2 cert;
            try
            {
                cert = new X509Certificate2(
                    pfx, (string?)null,
                    X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (PlatformNotSupportedException)
            {
                cert = new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable);
            }

            Array.Clear(pfx, 0, pfx.Length);
            return (cert, rsa);
        }
    }
}
