using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using TinyUa.CertGen;
using TinyUa.Explorer.Services;

namespace TinyUa.Security.Tests;

public class AuditToolRegressionTests
{
    [Fact]
    public async Task AsyncFileLoggerSurvivesSinkFailureAndCanResume()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"TinyUaLoggerTest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"TinyUa_{DateTime.Now:yyyy-MM-dd}.log");
        try
        {
            using var logger = new TinyUa.Core.Logging.FileLogger(dir, async: true);
            using (var blocked = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                logger.Log(TinyUa.Core.Logging.LogLevel.Information, null, "blocked write");
                using var deadline = new CancellationTokenSource(3000);
                while (logger.LastError == null) await Task.Delay(10, deadline.Token);
                Assert.True(logger.DroppedCount > 0);
            }
            logger.Log(TinyUa.Core.Logging.LogLevel.Information, null, "resumed write");
            logger.Dispose();
            Assert.Contains("resumed write", File.ReadAllText(path));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CertificateExportUsesSnapshotAndLoadsWithChosenPassword()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"TinyUaCertGenTest-{Guid.NewGuid():N}");
        try
        {
            var input = new CertificateFileGenerator.CertificateInput(dir, "Generated Test", "urn:tinyua:generated:test", 2048, 1, "export-password");
            var result = await Task.Run(() => CertificateFileGenerator.GenerateCertificate(input));
            using var certificate = new X509Certificate2(result.PfxPath, input.Password, X509KeyStorageFlags.EphemeralKeySet);
            using var publicCertificate = new X509Certificate2(result.DerPath);
            Assert.True(certificate.HasPrivateKey);
            Assert.Equal(certificate.RawData, publicCertificate.RawData);
            Assert.Equal(result.Thumbprint, certificate.Thumbprint);
            Assert.Throws<CryptographicException>(() => new X509Certificate2(result.PfxPath, "wrong-password", X509KeyStorageFlags.EphemeralKeySet));
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    [WindowsFact]
    public void LegacyPrivateKeyPasswordsMigrateAndNewPasswordsNeverAppearInJson()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"TinyUaSettingsTest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "settings.json");
        try
        {
            File.WriteAllText(path, "{\"first\":{\"PrivateKeyPassword\":\"legacy-secret\"},\"second\":{\"PrivateKeyPassword\":\"other-secret\"}}");
            var store = new SecuritySettingsStore(path);
            Assert.Equal("legacy-secret", store.Load("first")!.PrivateKeyPassword);
            var json = File.ReadAllText(path);
            Assert.DoesNotContain("legacy-secret", json);
            Assert.DoesNotContain("other-secret", json);
            Assert.Equal("other-secret", store.Load("second")!.PrivateKeyPassword);
            store.Save("first", new StoredSecuritySettings { PrivateKeyPassword = "new-secret" });
            Assert.Equal("new-secret", store.Load("first")!.PrivateKeyPassword);
            Assert.DoesNotContain("new-secret", File.ReadAllText(path));
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            Assert.False(document.RootElement.GetProperty("first").TryGetProperty("PrivateKeyPassword", out _));
        }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = "DPAPI requires Windows."; }
    }
}
