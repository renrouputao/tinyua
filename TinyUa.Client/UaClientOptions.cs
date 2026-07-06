using TinyUa.Core;
using TinyUa.Core.Security;

namespace TinyUa.Client
{
    /// <summary>
    /// Defines how the client handles operation failures.
    /// </summary>
    public enum ErrorMode
    {
        /// <summary>Throw exceptions on failure. Use when you need to distinguish and handle different error causes.</summary>
        Throw,

        /// <summary>Return <c>null</c> on failure. Use for best-effort scenarios where occasional failures are acceptable.</summary>
        ReturnNull
    }

    /// <summary>
    /// Complete configuration options for <see cref="UaClient"/>.
    /// Use <see cref="Default"/> for sensible defaults, or override via the
    /// <see cref="UaClient.ClientBuilder"/> fluent API returned by <see cref="UaClient.ConnectTo(string)"/>.
    /// </summary>
    public class UaClientOptions
    {
        /// <summary>Application name reported to the server for session diagnostics. Default <c>"TinyUaClient"</c>.</summary>
        public string ApplicationName { get; set; } = "TinyUaClient";

        /// <summary>Unique application URI. Auto-generated as <c>urn:tinyua:{Guid}</c> by default.</summary>
        public string ApplicationUri { get; set; } = $"urn:tinyua:{Guid.NewGuid()}";

        /// <summary>Product URI identifying the implementation. Default <c>"urn:openua:client"</c>.</summary>
        public string ProductUri { get; set; } = "urn:openua:client";

        /// <summary>
        /// Per-step network wait timeout in milliseconds. Controls the maximum wait for each socket send/receive
        /// and each reconnect attempt. Not the total Read/Write call timeout — if reconnect + retry are triggered,
        /// actual elapsed time may be 2–4x this value. Default 30000 (30 seconds). Set to 0 to use server default.
        /// </summary>
        public uint Timeout { get; set; } = 30000;

        /// <summary>Session lifetime in milliseconds. The server will close the session after this expires. Default 3600000 (1 hour).</summary>
        public double SessionTimeout { get; set; } = 3600000;

        /// <summary>Secure channel lifetime in milliseconds. The channel is automatically renewed before expiry. Default 3600000 (1 hour).</summary>
        public uint ChannelLifetime { get; set; } = 3600000;

        /// <summary>Maximum message size in bytes. 0 means unlimited (use server default).</summary>
        public uint MaxMessageSize { get; set; } = 0;

        /// <summary>Error handling strategy for failed operations. Default <see cref="Client.ErrorMode.Throw"/>.</summary>
        public ErrorMode ErrorMode { get; set; } = ErrorMode.Throw;

        /// <summary>Maximum reconnect attempts. Default -1 (infinite). Set to 0 to disable reconnect (equivalent to <c>WithoutReconnect()</c>).</summary>
        public int ReconnectMaxRetries { get; set; } = -1;

        /// <summary>Initial delay before the first reconnect attempt in milliseconds. Doubles each subsequent attempt up to <see cref="ReconnectMaxDelayMs"/>. Default 1000.</summary>
        public int ReconnectInitialDelayMs { get; set; } = 1000;

        /// <summary>Cap for exponential backoff delay in milliseconds. Default 30000 (30 seconds).</summary>
        public int ReconnectMaxDelayMs { get; set; } = 30000;

        /// <summary>Security configuration (policy, mode, identity, certificates).</summary>
        public SecurityOptions Security { get; set; } = new();

        /// <summary>Returns a read-only copy of default options.</summary>
        public static UaClientOptions Default => new();
    }

    /// <summary>
    /// Security options — security policy, message security mode, user identity, and certificate configuration.
    /// </summary>
    public class SecurityOptions
    {
        /// <summary>
        /// Security policy short name. Accepted values:
        /// <c>"None"</c>,
        /// <c>"Basic256Sha256"</c>,
        /// <c>"Aes128_Sha256_RsaOaep"</c>,
        /// <c>"Aes256_Sha256_RsaPss"</c>.
        /// Default <c>"None"</c>.
        /// </summary>
        public string Policy { get; set; } = "None";

        /// <summary>
        /// Message security mode. When using <c>WithSecurity(policy)</c> with a non-None policy,
        /// this is automatically set to <see cref="MessageSecurityMode.SignAndEncrypt"/>.
        /// </summary>
        public MessageSecurityMode Mode { get; set; } = MessageSecurityMode.None;

        /// <summary>User identity configuration.</summary>
        public UserIdentityOptions UserIdentity { get; set; } = new();

        /// <summary>Certificate configuration.</summary>
        public CertificateOptions Certificate { get; set; } = new();

        /// <summary>
        /// Automatically discover the server's certificate via GetEndpoints service. Default <c>true</c>.
        /// Disable to manually provide a server certificate.
        /// </summary>
        public bool AutoDiscoverServerCertificate { get; set; } = true;

        /// <summary>
        /// Automatically trust the server certificate (skip validation callback). Default <c>true</c>.
        /// Set to <c>false</c> in production and register a custom validation callback.
        /// </summary>
        public bool AutoAcceptServerCertificate { get; set; } = true;
    }

    /// <summary>
    /// User identity authentication options. Supports Anonymous, UserName/Password, and X509 Certificate.
    /// </summary>
    public class UserIdentityOptions
    {
        /// <summary>
        /// User token type. Default <see cref="UserTokenType.Anonymous"/>.
        /// Automatically set to <see cref="UserTokenType.UserName"/> when using <c>WithUserName()</c>.
        /// </summary>
        public UserTokenType Type { get; set; } = UserTokenType.Anonymous;

        /// <summary>Username (only used with <see cref="UserTokenType.UserName"/>).</summary>
        public string? Username { get; set; }

        /// <summary>
        /// Password (only used with <see cref="UserTokenType.UserName"/>).
        /// Encrypted with RSA-OAEP using the server's certificate before transmission — never sent in cleartext.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>X509 certificate file path (only used with <see cref="UserTokenType.Certificate"/>).</summary>
        public string? CertificatePath { get; set; }

        /// <summary>X509 private key file path (only used with <see cref="UserTokenType.Certificate"/>).</summary>
        public string? PrivateKeyPath { get; set; }
    }

    /// <summary>
    /// Client certificate options. Supports auto-generation of self-signed certificates or specifying an existing one.
    /// </summary>
    public class CertificateOptions
    {
        /// <summary>Certificate file path. Leave empty to auto-generate with <see cref="AutoGenerate"/>.</summary>
        public string? CertificatePath { get; set; }

        /// <summary>Private key file path. Leave empty to auto-generate with <see cref="AutoGenerate"/>.</summary>
        public string? PrivateKeyPath { get; set; }

        /// <summary>Private key password (only needed for PFX format certificates).</summary>
        public string? PrivateKeyPassword { get; set; }

        /// <summary>
        /// Auto-generate a self-signed client certificate at runtime. Default <c>true</c>.
        /// Set to <c>false</c> to provide an existing certificate via <see cref="CertificatePath"/>.
        /// </summary>
        public bool AutoGenerate { get; set; } = true;

        /// <summary>RSA key size in bits for auto-generated certificates. Default 2048.</summary>
        public int KeySize { get; set; } = 2048;

        /// <summary>Validity period in years for auto-generated certificates. Default 5.</summary>
        public int ValidityYears { get; set; } = 5;
    }
}
