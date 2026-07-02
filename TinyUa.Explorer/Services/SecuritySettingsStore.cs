using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TinyUa.Core.Security;

namespace TinyUa.Explorer.Services
{
    /// <summary>
    /// Persisted security selection for a given endpoint URL. The password is stored
    /// DPAPI-encrypted (CurrentUser scope) so the JSON file on disk never contains
    /// plaintext credentials.
    /// </summary>
    public record StoredSecuritySettings
    {
        public string Policy { get; init; } = "None";
        public MessageSecurityMode Mode { get; init; } = MessageSecurityMode.None;
        public UserTokenType TokenType { get; init; } = UserTokenType.Anonymous;
        public string? Username { get; init; }
        public string? EncryptedPasswordBase64 { get; init; }

        /// <summary>Decrypted password (in-memory only). Never serialized — marked
        /// <see cref="JsonIgnoreAttribute"/> so it can never leak to disk.</summary>
        [JsonIgnore]
        public string? PlainPassword { get; init; }
    }

    /// <summary>
    /// Persists per-URL security selections to
    /// <c>%AppData%/TinyUa.Explorer/security_settings.json</c>, encrypting passwords with
    /// Windows DPAPI (CurrentUser). Mirrors the endpoint_history persistence pattern in
    /// <c>MainViewModel</c>.
    /// </summary>
    public class SecuritySettingsStore
    {
        private static readonly string SettingsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "TinyUa.Explorer", "security_settings.json");

        // Fixed entropy prevents other apps' DPAPI blobs from being misread here; it need
        // not be secret — its purpose is namespacing, not confidentiality.
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("TinyUa.Explorer.Pwd");

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        /// <summary>Loads the saved settings for <paramref name="endpointUrl"/>, decrypting
        /// the password into <see cref="StoredSecuritySettings.PlainPassword"/>. Returns null
        /// (with no plaintext) if nothing is saved or decryption fails (e.g. different
        /// Windows user / different machine) — callers should re-prompt for credentials.</summary>
        public StoredSecuritySettings? Load(string endpointUrl)
        {
            try
            {
                if (!File.Exists(SettingsFilePath)) return null;
                var json = File.ReadAllText(SettingsFilePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, StoredSecuritySettings>>(json, JsonOptions);
                if (dict == null || !dict.TryGetValue(endpointUrl, out var s)) return null;

                var plain = TryDecryptPassword(s.EncryptedPasswordBase64);
                return s with { PlainPassword = plain };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Saves (or replaces) the settings for <paramref name="endpointUrl"/>.
        /// Best-effort: never throws — persistence failures only degrade the "remember me"
        /// experience, they don't break connection.</summary>
        public void Save(string endpointUrl, StoredSecuritySettings settings)
        {
            try
            {
                var dict = new Dictionary<string, StoredSecuritySettings>();
                if (File.Exists(SettingsFilePath))
                {
                    var json = File.ReadAllText(SettingsFilePath);
                    var existing = JsonSerializer.Deserialize<Dictionary<string, StoredSecuritySettings>>(json, JsonOptions);
                    if (existing != null) dict = existing;
                }
                dict[endpointUrl] = settings;
                var dir = Path.GetDirectoryName(SettingsFilePath);
                if (dir != null) Directory.CreateDirectory(dir);
                File.WriteAllText(SettingsFilePath, JsonSerializer.Serialize(dict, JsonOptions));
            }
            catch
            {
                /* best-effort persistence */
            }
        }

        /// <summary>Encrypts a plaintext password with DPAPI (CurrentUser) and returns the
        /// base64-encoded blob, or null if the input is empty or encryption fails.</summary>
        public static string? EncryptPassword(string? plain)
        {
            if (string.IsNullOrEmpty(plain)) return null;
            try
            {
                var bytes = Encoding.UTF8.GetBytes(plain);
                var encrypted = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(encrypted);
            }
            catch
            {
                return null;
            }
        }

        private static string? TryDecryptPassword(string? base64)
        {
            if (string.IsNullOrEmpty(base64)) return null;
            try
            {
                var encrypted = Convert.FromBase64String(base64);
                var bytes = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                // DPAPI blob was created under a different user/machine, or was tampered with.
                // Treat as "no saved password" — caller will prompt the user.
                return null;
            }
        }
    }
}
