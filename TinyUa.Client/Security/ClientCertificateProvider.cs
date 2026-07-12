using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Logging;
using TinyUa.Core.Security.Certificates;

namespace TinyUa.Client.Security
{
    /// <summary>
    /// Loads the client certificate from disk or generates a self-signed one, and extracts the
    /// application URI embedded in the certificate's SAN extension so the session can present a
    /// matching ApplicationUri.
    /// </summary>
    internal static class ClientCertificateProvider
    {
        /// <summary>
        /// Returns the client certificate (or null when none is configured and auto-generation is
        /// off) plus the URI from a loaded certificate's SAN (null for generated certificates —
        /// they already carry the requested URI). The caller decides whether to adopt the URI.
        /// </summary>
        internal static (X509Certificate2? Certificate, string? CertificateUri) LoadOrGenerate(
            CertificateOptions certOptions, string applicationName, string applicationUri, ILogger logger)
        {
            // Try loading from file first
            if (!string.IsNullOrEmpty(certOptions.CertificatePath) && File.Exists(certOptions.CertificatePath))
            {
                X509Certificate2 cert;
                if (!string.IsNullOrEmpty(certOptions.PrivateKeyPath))
                {
                    (cert, _) = CertificateLoader.LoadCertificateWithKey(
                        certOptions.CertificatePath!, certOptions.PrivateKeyPath!);
                }
                else
                {
                    cert = CertificateLoader.LoadCertificate(certOptions.CertificatePath!, certOptions.PrivateKeyPassword);
                }

                return (cert, GetUriFromCertificate(cert));
            }

            if (certOptions.AutoGenerate)
            {
                logger.LogDebug($"Auto-generating self-signed certificate " +
                    $"(CN={applicationName}, URI={applicationUri})...");
                var (cert, _) = CertificateGenerator.CreateSelfSigned(
                    applicationName,
                    applicationUri,
                    certOptions.KeySize,
                    certOptions.ValidityYears);

                // Save to file if path is specified
                if (!string.IsNullOrEmpty(certOptions.CertificatePath))
                {
                    var pfxPassword = certOptions.PrivateKeyPassword ?? "";
                    var pfxBytes = string.IsNullOrEmpty(pfxPassword)
                        ? cert.Export(X509ContentType.Pfx)
                        : cert.Export(X509ContentType.Pfx, pfxPassword);
                    File.WriteAllBytes(certOptions.CertificatePath, pfxBytes);

                    // Also save DER format for servers that don't accept PFX
                    var derPath = Path.ChangeExtension(certOptions.CertificatePath, ".der");
                    File.WriteAllBytes(derPath, cert.RawData);
                }

                return (cert, null);
            }

            return (null, null);
        }

        internal static string? GetUriFromCertificate(X509Certificate2 cert)
        {
            try
            {
                // SAN OID = 2.5.29.17. Parse the ASN.1 GeneralNames directly instead of the
                // Format(false) display text — that text is CryptoAPI-specific ("URL=...") and
                // has a different shape on Linux/macOS, which made URI extraction silently fail.
                var sanExt = cert.Extensions["2.5.29.17"];
                if (sanExt == null) return null;

                var reader = new System.Formats.Asn1.AsnReader(
                    sanExt.RawData, System.Formats.Asn1.AsnEncodingRules.DER);
                var generalNames = reader.ReadSequence();
                var uriTag = new System.Formats.Asn1.Asn1Tag(
                    System.Formats.Asn1.TagClass.ContextSpecific, 6);
                while (generalNames.HasData)
                {
                    if (generalNames.PeekTag().HasSameClassAndValue(uriTag))
                        return generalNames.ReadCharacterString(
                            System.Formats.Asn1.UniversalTagNumber.IA5String, uriTag);
                    generalNames.ReadEncodedValue();
                }
            }
            catch { }
            return null;
        }
    }
}
