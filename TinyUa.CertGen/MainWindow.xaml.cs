using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using Microsoft.Win32;

namespace TinyUa.CertGen;

public partial class MainWindow : Window
{
    private readonly CertGenViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
    }

    private void BrowseOutputDir(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Select output directory" };
        if (dlg.ShowDialog() == true)
            _vm.OutputDirectory = dlg.FolderName;
    }

    private async void Generate_Click(object sender, RoutedEventArgs e)
    {
        if (!ValidateInputs()) return;

        _vm.IsNotGenerating = false;
        _vm.ResultText = "Generating...";

        try
        {
            await Task.Run(() => GenerateCertificate());
            _vm.ResultText = BuildSuccessMessage();
        }
        catch (Exception ex)
        {
            _vm.ResultText = $"FAILED: {ex.Message}";
        }
        finally
        {
            _vm.IsNotGenerating = true;
        }
    }

    private bool ValidateInputs()
    {
        if (string.IsNullOrWhiteSpace(_vm.CommonName))
        {
            MessageBox.Show("Common Name is required.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        if (string.IsNullOrWhiteSpace(_vm.ApplicationUri))
        {
            MessageBox.Show("Application URI is required.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        if (string.IsNullOrWhiteSpace(_vm.OutputDirectory))
        {
            MessageBox.Show("Output directory is required.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        if (!int.TryParse(_vm.ValidityYears, out int yrs) || yrs < 1 || yrs > 50)
        {
            MessageBox.Show("Validity must be 1-50 years.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        return true;
    }

    private void GenerateCertificate()
    {
        var dir = _vm.OutputDirectory;
        Directory.CreateDirectory(dir);

        var keySize = _vm.SelectedKeySize;
        using var rsa = RSA.Create(keySize);

        var req = new CertificateRequest(
            $"CN={_vm.CommonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // SAN: URI + DNS
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(_vm.ApplicationUri));
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
        var notAfter = DateTimeOffset.UtcNow.AddYears(int.Parse(_vm.ValidityYears));

        var ephemeral = req.CreateSelfSigned(notBefore, notAfter);
        byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx);
        ephemeral.Dispose();

        // Reload with exportable key
        var password = PfxPasswordBox.Password;
        var cert = string.IsNullOrEmpty(password)
            ? new X509Certificate2(pfxBytes, (string?)null, X509KeyStorageFlags.Exportable)
            : new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.Exportable);

        // Save files
        var safeName = SanitizeFileName(_vm.CommonName);
        _vm.PfxPath = Path.Combine(dir, $"{safeName}.pfx");
        _vm.DerPath = Path.Combine(dir, $"{safeName}.der");
        _vm.Thumbprint = cert.Thumbprint;
        _vm.ExpiryDate = cert.NotAfter.ToString("yyyy-MM-dd");

        var exportPassword = string.IsNullOrEmpty(password) ? (string?)null : password;
        var finalPfx = string.IsNullOrEmpty(exportPassword)
            ? cert.Export(X509ContentType.Pfx)
            : cert.Export(X509ContentType.Pfx, exportPassword);
        File.WriteAllBytes(_vm.PfxPath, finalPfx);
        File.WriteAllBytes(_vm.DerPath, cert.RawData);

        cert.Dispose();
    }

    private static string SanitizeFileName(string name) =>
        string.Join("_", name.Split(Path.GetInvalidFileNameChars()));

    private string BuildSuccessMessage()
    {
        return $"Certificate generated successfully!\n\n"
            + $"  CN:          {_vm.CommonName}\n"
            + $"  URI:         {_vm.ApplicationUri}\n"
            + $"  Thumbprint:  {_vm.Thumbprint}\n"
            + $"  Key Size:    {_vm.SelectedKeySize} bits\n"
            + $"  Expires:     {_vm.ExpiryDate}\n\n"
            + $"  PFX: {_vm.PfxPath}\n"
            + $"  DER: {_vm.DerPath}\n\n"
            + $"TinyUa code:\n"
            + $"  .WithSecurity(opts => opts.Certificate = new CertificateOptions\n"
            + $"  {{\n"
            + $"      CertificatePath = @\"{_vm.PfxPath}\",\n"
            + $"      PrivateKeyPassword = \"{PfxPasswordBox.Password}\",\n"
            + $"      AutoGenerate = false\n"
            + $"  }})";
    }
}

public class CertGenViewModel : INotifyPropertyChanged
{
    private string _commonName = "TinyUa Client";
    private string _applicationUri = "urn:tinyua:client";
    private int _selectedKeySize = 2048;
    private string _validityYears = "10";
    private string _outputDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private string _resultText = "";
    private bool _isNotGenerating = true;

    public string PfxPath = "", DerPath = "", Thumbprint = "", ExpiryDate = "";

    public int[] KeySizes { get; } = [2048, 3072, 4096];

    public string CommonName { get => _commonName; set { _commonName = value; OnPropertyChanged(); } }
    public string ApplicationUri { get => _applicationUri; set { _applicationUri = value; OnPropertyChanged(); } }
    public int SelectedKeySize { get => _selectedKeySize; set { _selectedKeySize = value; OnPropertyChanged(); } }
    public string ValidityYears { get => _validityYears; set { _validityYears = value; OnPropertyChanged(); } }
    public string OutputDirectory { get => _outputDirectory; set { _outputDirectory = value; OnPropertyChanged(); } }
    public string ResultText { get => _resultText; set { _resultText = value; OnPropertyChanged(); } }
    public bool IsNotGenerating { get => _isNotGenerating; set { _isNotGenerating = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
