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

        // Certificate options
        public string? CertificatePath { get; init; }
        [JsonIgnore]
        public string? PrivateKeyPassword { get; init; }
        public string? EncryptedPrivateKeyPasswordBase64 { get; init; }
        [JsonPropertyName("PrivateKeyPassword")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? LegacyPrivateKeyPassword { get; init; }
        public bool AutoGenerateCert { get; init; } = true;

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
        private readonly string SettingsFilePath;
        private static readonly object SettingsLock = new();

        public SecuritySettingsStore() : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "TinyUa.Explorer", "security_settings.json"))
        { }

        internal SecuritySettingsStore(string path) => SettingsFilePath = path;

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
            lock (SettingsLock)
            {
                try
                {
                    if (!File.Exists(SettingsFilePath)) return null;
                    var json = File.ReadAllText(SettingsFilePath);
                    var dict = JsonSerializer.Deserialize<Dictionary<string, StoredSecuritySettings>>(json, JsonOptions);
                    if (dict == null || !dict.TryGetValue(endpointUrl, out var s)) return null;

                    var plain = TryDecryptPassword(s.EncryptedPasswordBase64);
                    var keyPassword = TryDecryptPassword(s.EncryptedPrivateKeyPasswordBase64) ?? s.LegacyPrivateKeyPassword;
                    var loaded = s with { PlainPassword = plain, PrivateKeyPassword = keyPassword };
                    if (dict.Values.Any(x => x.LegacyPrivateKeyPassword != null)) Save(endpointUrl, loaded);
                    return loaded with { LegacyPrivateKeyPassword = null };
                }
                catch
                {
                    return null;
                }
            }
        }

        /// <summary>Saves (or replaces) the settings for <paramref name="endpointUrl"/>.
        /// Best-effort: never throws — persistence failures only degrade the "remember me"
        /// experience, they don't break connection.</summary>
        public void Save(string endpointUrl, StoredSecuritySettings settings)
        {
            lock (SettingsLock)
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
                    foreach (var key in dict.Keys.ToArray())
                    {
                        var entry = dict[key];
                        var password = entry.PrivateKeyPassword ?? entry.LegacyPrivateKeyPassword;
                        var encrypted = password != null ? EncryptPassword(password) : entry.EncryptedPrivateKeyPasswordBase64;
                        if (!string.IsNullOrEmpty(password) && encrypted == null)
                            throw new CryptographicException("Cannot protect certificate password.");
                        dict[key] = entry with { EncryptedPrivateKeyPasswordBase64 = encrypted, LegacyPrivateKeyPassword = null };
                    }
                    var dir = Path.GetDirectoryName(SettingsFilePath);
                    if (dir != null) Directory.CreateDirectory(dir);
                    var temporary = SettingsFilePath + ".tmp";
                    File.WriteAllText(temporary, JsonSerializer.Serialize(dict, JsonOptions));
                    File.Move(temporary, SettingsFilePath, overwrite: true);
                }
                catch
                {
                    /* best-effort persistence */
                }
            }
        }

        /// <summary>Encrypts a plaintext password with DPAPI (CurrentUser) and returns the
        /// base64-encoded blob, or null if the input is empty or encryption fails.</summary>
        public static string? EncryptPassword(string? plain)
        {
            if (!OperatingSystem.IsWindows()) return null;
            if (string.IsNullOrEmpty(plain)) return null;
            try
            {
                var bytes = Encoding.UTF8.GetBytes(plain);
                try { return Convert.ToBase64String(ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser)); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch
            {
                return null;
            }
        }

        private static string? TryDecryptPassword(string? base64)
        {
            if (!OperatingSystem.IsWindows()) return null;
            if (string.IsNullOrEmpty(base64)) return null;
            try
            {
                var encrypted = Convert.FromBase64String(base64);
                var bytes = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
                try { return Encoding.UTF8.GetString(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
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
