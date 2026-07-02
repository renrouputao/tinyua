using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TinyUa.Core.Client.Discovery;
using TinyUa.Core.Security;
using TinyUa.Explorer.Services;

namespace TinyUa.Explorer.ViewModels
{
    /// <summary>
    /// Result of the security selection dialog. Carries the user's choices back to
    /// <see cref="MainViewModel"/>, which persists them and feeds them into
    /// <c>UaClientOptions.Security</c>.
    /// </summary>
    public record SecuritySelectionResult(
        string Policy,
        MessageSecurityMode Mode,
        UserTokenType TokenType,
        string? Username,
        string? Password);

    /// <summary>
    /// View-model for the endpoint security discovery/selection dialog. On construction it
    /// immediately fires <see cref="DiscoverAsync"/> to enumerate the server's endpoints via
    /// <see cref="EndpointDiscoverer"/>. When the user picks an endpoint + identity and
    /// confirms, <see cref="ToResult"/> produces the selection for the caller.
    /// </summary>
    public partial class SecuritySelectionViewModel : ObservableObject
    {
        private readonly StoredSecuritySettings? _saved;

        // Remembered so OnSelectedEndpointChanged can pre-select the saved token type when
        // the discovered endpoint list arrives.
        private readonly UserTokenType _savedTokenType;

        /// <summary>The endpoint URL being discovered. Display-only.</summary>
        public string Url { get; }

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        private IReadOnlyList<DiscoveredEndpoint> _endpoints = Array.Empty<DiscoveredEndpoint>();

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        [NotifyPropertyChangedFor(nameof(IsNoneWithUserName))]
        private DiscoveredEndpoint? _selectedEndpoint;

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        [NotifyPropertyChangedFor(nameof(NeedsCredentials))]
        [NotifyPropertyChangedFor(nameof(IsNoneWithUserName))]
        private UserTokenType _selectedTokenType = UserTokenType.Anonymous;

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        private string _username = "";

        /// <summary>Set by the dialog code-behind from the PasswordBox (WPF cannot two-way
        /// bind passwords). Not bound in XAML.</summary>
        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        private string _password = "";

        [ObservableProperty]
        [NotifyCanExecuteChangedFor(nameof(OkCommand))]
        private bool _isDiscovering = true;

        [ObservableProperty]
        private bool _hasError;

        [ObservableProperty]
        private string _errorMessage = "";

        /// <summary>Set to true by <see cref="OkCommand"/>; the dialog reads this after
        /// ShowDialog returns to decide what to yield.</summary>
        [ObservableProperty]
        private bool _dialogResult;

        /// <summary>User token types advertised by the selected endpoint, refreshed whenever
        /// <see cref="SelectedEndpoint"/> changes.</summary>
        public ObservableCollection<UserTokenType> AvailableTokenTypes { get; } = new();

        /// <summary>True when the selected token type requires username/password entry.</summary>
        public bool NeedsCredentials => SelectedTokenType == UserTokenType.UserName;

        /// <summary>True when None policy is combined with a UserName token — the password
        /// would travel in cleartext, so the UI warns the user.</summary>
        public bool IsNoneWithUserName =>
            SelectedEndpoint?.IsSecure == false && SelectedTokenType == UserTokenType.UserName;

        public SecuritySelectionViewModel(string url, StoredSecuritySettings? saved)
        {
            Url = url;
            _saved = saved;
            _savedTokenType = saved?.TokenType ?? UserTokenType.Anonymous;
            // Fire-and-forget; the dialog is already on screen showing the ProgressRing.
            _ = DiscoverAsync();
        }

        [RelayCommand]
        private async Task DiscoverAsync()
        {
            IsDiscovering = true;
            HasError = false;
            ErrorMessage = "";
            try
            {
                var found = await EndpointDiscoverer.DiscoverAsync(Url).ConfigureAwait(true);
                Endpoints = found;

                if (found.Count == 0)
                {
                    HasError = true;
                    ErrorMessage = "Server returned no endpoints.";
                }
                else
                {
                    // Pre-select: saved (Policy, Mode) if present, otherwise the first (most secure).
                    DiscoveredEndpoint? match = null;
                    if (_saved != null)
                    {
                        foreach (var ep in found)
                        {
                            if (string.Equals(ep.SecurityPolicy, _saved.Policy, StringComparison.OrdinalIgnoreCase)
                                && ep.SecurityMode == _saved.Mode)
                            {
                                match = ep;
                                break;
                            }
                        }
                    }
                    SelectedEndpoint = match ?? found[0];

                    // Backfill identity from saved settings (OnSelectedEndpointChanged already
                    // picked the token type, butUsername/Password are handled here).
                    if (_saved != null)
                    {
                        Username = _saved.Username ?? "";
                        Password = _saved.PlainPassword ?? "";
                    }
                }
            }
            catch (Exception ex)
            {
                HasError = true;
                ErrorMessage = $"Discovery failed: {ex.Message}";
            }
            finally
            {
                IsDiscovering = false;
            }
        }

        partial void OnSelectedEndpointChanged(DiscoveredEndpoint? value)
        {
            AvailableTokenTypes.Clear();
            if (value != null)
            {
                foreach (var t in value.UserTokenTypes)
                    AvailableTokenTypes.Add(t);

                // Prefer the saved token type, else Anonymous, else the first advertised.
                if (AvailableTokenTypes.Contains(_savedTokenType))
                    SelectedTokenType = _savedTokenType;
                else if (AvailableTokenTypes.Contains(UserTokenType.Anonymous))
                    SelectedTokenType = UserTokenType.Anonymous;
                else if (AvailableTokenTypes.Count > 0)
                    SelectedTokenType = AvailableTokenTypes[0];
            }
            else
            {
                SelectedTokenType = UserTokenType.Anonymous;
            }
        }

        private bool CanOk()
        {
            if (IsDiscovering || SelectedEndpoint == null)
                return false;
            if (NeedsCredentials)
                return !string.IsNullOrWhiteSpace(Username) && !string.IsNullOrEmpty(Password);
            return true;
        }

        [RelayCommand(CanExecute = nameof(CanOk))]
        private void Ok()
        {
            DialogResult = true;
            RequestClose?.Invoke();
        }

        [RelayCommand]
        private void Cancel()
        {
            DialogResult = false;
            RequestClose?.Invoke();
        }

        /// <summary>Raised by Ok/Cancel to ask the view to close itself.</summary>
        public event Action? RequestClose;

        /// <summary>Builds the result from the current selection. Call only when
        /// <see cref="DialogResult"/> is true.</summary>
        public SecuritySelectionResult ToResult() => new(
            Policy: SelectedEndpoint!.SecurityPolicy,
            Mode: SelectedEndpoint!.SecurityMode,
            TokenType: SelectedTokenType,
            Username: NeedsCredentials ? Username : null,
            Password: NeedsCredentials ? Password : null);
    }
}
