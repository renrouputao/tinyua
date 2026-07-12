using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TinyUa.Core.Security.Certificates
{
    internal static class CertificateLoader
    {
        internal static X509Certificate2 LoadCertificate(string path, string? password = null)
        {
            var bytes = File.ReadAllBytes(path);
            return LoadCertificate(bytes, password);
        }

        internal static X509Certificate2 LoadCertificate(byte[] data, string? password = null)
        {
            if (IsPem(data))
                return X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(data));
            return password != null
                ? new X509Certificate2(data, password)
                : new X509Certificate2(data);
        }

        /// <summary>
        /// Detects a PEM-encoded payload by looking for the "-----BEGIN" armor at the start
        /// (after optional leading whitespace/BOM), rather than testing a single byte. DER data
        /// starts with an ASN.1 SEQUENCE tag (0x30) and never matches this.
        /// </summary>
        private static bool IsPem(byte[] data)
        {
            if (data == null || data.Length < 11)
                return false;

            int i = 0;
            // Skip a UTF-8 BOM if present.
            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
                i = 3;
            // Skip leading ASCII whitespace.
            while (i < data.Length && (data[i] == 0x20 || data[i] == 0x09 || data[i] == 0x0D || data[i] == 0x0A))
                i++;

            ReadOnlySpan<byte> marker = "-----BEGIN"u8;
            if (i + marker.Length > data.Length)
                return false;
            return data.AsSpan(i, marker.Length).SequenceEqual(marker);
        }

        internal static RSA LoadPrivateKey(string path)
        {
            var bytes = File.ReadAllBytes(path);
            return LoadPrivateKey(bytes);
        }

        internal static RSA LoadPrivateKey(byte[] data)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(Encoding.ASCII.GetString(data));
            return rsa;
        }

        internal static (X509Certificate2 Certificate, RSA PrivateKey) LoadCertificateWithKey(
            string certPath, string keyPath)
        {
            var cert = LoadCertificate(certPath);
            var key = LoadPrivateKey(keyPath);
            var combined = cert.CopyWithPrivateKey(key);
            cert.Dispose();
            return (combined, key);
        }
    }
}
