using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TinyUa.Core.Security.Certificates
{
    internal static class CertificateLoader
    {
        internal static X509Certificate2 LoadCertificate(string path)
        {
            var bytes = File.ReadAllBytes(path);
            return LoadCertificate(bytes);
        }

        internal static X509Certificate2 LoadCertificate(byte[] data)
        {
            if (data.Length > 5 && data[0] == 0x2D)
                return X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(data));
            return new X509Certificate2(data);
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
