using System.ComponentModel;
using System.Windows;
using Wpf.Ui.Controls;
using TinyUa.Explorer.Services;
using TinyUa.Explorer.ViewModels;

namespace TinyUa.Explorer.Views
{
    /// <summary>
    /// Code-behind for <see cref="SecuritySelectionDialog"/>. Bridges the WPF PasswordBox
    /// (which cannot two-way bind its password) to <see cref="SecuritySelectionViewModel.Password"/>,
    /// and provides the static <see cref="Show"/> entry point used by MainViewModel.
    /// </summary>
    public partial class SecuritySelectionDialog : FluentWindow
    {
        private readonly SecuritySelectionViewModel _vm;

        public SecuritySelectionDialog(SecuritySelectionViewModel vm)
        {
            InitializeComponent();
            _vm = vm;
            DataContext = vm;

            // Bridge PasswordBox ↔ VM.Password. The VM may set Password programmatically
            // (e.g. from saved settings after discovery); sync it into the box. The box in
            // turn pushes user input back into the VM.
            vm.PropertyChanged += OnVmPropertyChanged;
            PwdBox.PasswordChanged += (_, _) =>
            {
                if (_vm.Password != PwdBox.Password)
                    _vm.Password = PwdBox.Password;
            };

            CertPwdBox.PasswordChanged += (_, _) =>
            {
                if (_vm.CertPrivateKeyPassword != CertPwdBox.Password)
                    _vm.CertPrivateKeyPassword = CertPwdBox.Password;
            };

            vm.RequestClose += () => Close();
        }

        private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            // When the VM's Password changes (programmatic, e.g. saved-credential backfill),
            // or when the credential panel becomes visible, mirror it into the PasswordBox.
            if (e.PropertyName == nameof(SecuritySelectionViewModel.Password)
                || e.PropertyName == nameof(SecuritySelectionViewModel.NeedsCredentials))
            {
                if (PwdBox.Password != _vm.Password)
                    PwdBox.Password = _vm.Password ?? "";
            }
        }

        /// <summary>
        /// Opens the security selection dialog for <paramref name="url"/>, pre-populating it
        /// with any saved settings. Returns the user's selection, or null if cancelled.
        /// </summary>
        public static SecuritySelectionResult? Show(string url, StoredSecuritySettings? saved, Window owner)
        {
            var vm = new SecuritySelectionViewModel(url, saved);
            var dialog = new SecuritySelectionDialog(vm)
            {
                Owner = owner
            };
            dialog.ShowDialog();
            return vm.DialogResult ? vm.ToResult() : null;
        }

        protected override void OnClosed(EventArgs e)
        {
            _vm.PropertyChanged -= OnVmPropertyChanged;
            base.OnClosed(e);
        }
    }
}
