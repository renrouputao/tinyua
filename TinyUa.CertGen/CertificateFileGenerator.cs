using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TinyUa.CertGen;

internal static class CertificateFileGenerator
{
    internal sealed record CertificateInput(string Directory, string Name, string Uri, int KeySize, int Years, string Password);
    internal sealed record CertificateResult(string PfxPath, string DerPath, string Thumbprint, string ExpiryDate);

    internal static CertificateResult GenerateCertificate(CertificateInput input)
    {
        var dir = input.Directory;
        Directory.CreateDirectory(dir);

        var keySize = input.KeySize;
        using var rsa = RSA.Create(keySize);

        var req = new CertificateRequest(
            $"CN={input.Name}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // SAN: URI + DNS
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(input.Uri));
        try { sanBuilder.AddDnsName(Environment.MachineName); }
        catch { sanBuilder.AddDnsName("localhost"); }
        req.CertificateExtensions.Add(sanBuilder.Build());

        // Basic constraints
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

        // Key usage
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
            | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.NonRepudiation,
            true));

        // EKU: client + server auth
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2"), new("1.3.6.1.5.5.7.3.1") }, true));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(input.Years);

        using var cert = req.CreateSelfSigned(notBefore, notAfter);
        var safeName = SanitizeFileName(input.Name);
        if (string.IsNullOrWhiteSpace(safeName)) throw new ArgumentException("Certificate filename is empty.");
        var pfxPath = Path.Combine(dir, $"{safeName}.pfx");
        var derPath = Path.Combine(dir, $"{safeName}.der");
        var finalPfx = cert.Export(X509ContentType.Pfx, input.Password);
        try { File.WriteAllBytes(pfxPath, finalPfx); }
        finally { CryptographicOperations.ZeroMemory(finalPfx); }
        File.WriteAllBytes(derPath, cert.RawData);
        return new(pfxPath, derPath, cert.Thumbprint, cert.NotAfter.ToString("yyyy-MM-dd"));
    }

    private static string SanitizeFileName(string name) =>
        string.Join("_", name.Split(Path.GetInvalidFileNameChars()));

}
