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
            var input = new CertificateFileGenerator.CertificateInput(_vm.OutputDirectory, _vm.CommonName, _vm.ApplicationUri,
                _vm.SelectedKeySize, int.Parse(_vm.ValidityYears), PfxPasswordBox.Password);
            var result = await Task.Run(() => CertificateFileGenerator.GenerateCertificate(input));
            _vm.PfxPath = result.PfxPath;
            _vm.DerPath = result.DerPath;
            _vm.Thumbprint = result.Thumbprint;
            _vm.ExpiryDate = result.ExpiryDate;
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
            + $"      PrivateKeyPassword = \"[password]\",\n"
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
