using TinyUa.Core;
using TinyUa.Core.Security;
using TinyUa.Client.Subscriptions;

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

        /// <summary>
        /// Idle threshold in milliseconds for the session keep-alive heartbeat. The heartbeat —
        /// a lightweight read of <c>Server.ServerStatus.State</c> (i=2259) — is only sent when
        /// no request has gone out for this long; ordinary reads/writes/publish requests already
        /// refresh the session lifetime, so under continuous traffic no heartbeat is sent at all.
        /// When the session stays idle, this value becomes the heartbeat interval.
        /// 0 (default) = automatic: a quarter of <see cref="SessionTimeout"/>, clamped to
        /// [1000, 60000] ms. A negative value disables the heartbeat.
        /// </summary>
        public int SessionKeepAliveIntervalMs { get; set; } = 0;

        /// <summary>Secure channel lifetime in milliseconds. The channel is automatically renewed before expiry. Default 3600000 (1 hour).</summary>
        public uint ChannelLifetime { get; set; } = 3600000;

        /// <summary>
        /// Perform a warmup read of <c>Server.ServerStatus.State</c> (i=2259) immediately after the
        /// session is activated. This serves two purposes: (1) it confirms the server is responsive
        /// before the first application request, and (2) it pre-compiles (JIT) the Read codec path —
        /// <c>ReadRequest.Encode</c>, <c>ReadResponse.Decode</c>, <c>DataValue</c>/<c>Variant</c>
        /// decoding — so the caller's first business Read doesn't pay the one-time ~4ms JIT cost.
        /// Default <c>true</c>. Set to <c>false</c> to skip (e.g. when connecting to a known-slow server).
        /// </summary>
        public bool WarmupOnConnect { get; set; } = true;

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

        /// <summary>
        /// Number of Publish requests the session-level publish engine keeps in flight. Default 2.
        /// Higher values reduce notification latency under load at the cost of more queued
        /// requests on the server (bounded by the server's MaxPublishRequestCount).
        /// </summary>
        public int MaxPublishRequests { get; set; } = 2;

        /// <summary>
        /// Notification callback dispatch configuration. Each subscription receives responses
        /// through its own bounded, ordered queue before user callbacks are invoked.
        /// </summary>
        public SubscriptionDispatchOptions SubscriptionDispatch { get; set; } = new();

        /// <summary>Security configuration (policy, mode, identity, certificates).</summary>
        public SecurityOptions Security { get; set; } = new();

        /// <summary>Returns a read-only copy of default options.</summary>
        public static UaClientOptions Default => new();

        /// <summary>
        /// Creates a deep copy. <see cref="UaClient"/> snapshots its options at construction so
        /// that later mutations of the original object cannot affect a running client.
        /// </summary>
        public UaClientOptions Clone() => new()
        {
            ApplicationName = ApplicationName,
            ApplicationUri = ApplicationUri,
            ProductUri = ProductUri,
            Timeout = Timeout,
            SessionTimeout = SessionTimeout,
            SessionKeepAliveIntervalMs = SessionKeepAliveIntervalMs,
            ChannelLifetime = ChannelLifetime,
            WarmupOnConnect = WarmupOnConnect,
            MaxMessageSize = MaxMessageSize,
            ErrorMode = ErrorMode,
            ReconnectMaxRetries = ReconnectMaxRetries,
            ReconnectInitialDelayMs = ReconnectInitialDelayMs,
            ReconnectMaxDelayMs = ReconnectMaxDelayMs,
            MaxPublishRequests = MaxPublishRequests,
            SubscriptionDispatch = SubscriptionDispatch.Clone(),
            Security = Security.Clone()
        };
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

        /// <summary>Creates a deep copy of these security options.</summary>
        public SecurityOptions Clone() => new()
        {
            Policy = Policy,
            Mode = Mode,
            UserIdentity = UserIdentity.Clone(),
            Certificate = Certificate.Clone(),
            AutoDiscoverServerCertificate = AutoDiscoverServerCertificate,
            AutoAcceptServerCertificate = AutoAcceptServerCertificate
        };
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

        /// <summary>Creates a copy of these user identity options.</summary>
        public UserIdentityOptions Clone() => new()
        {
            Type = Type,
            Username = Username,
            Password = Password,
            CertificatePath = CertificatePath,
            PrivateKeyPath = PrivateKeyPath
        };
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

        /// <summary>Creates a copy of these certificate options.</summary>
        public CertificateOptions Clone() => new()
        {
            CertificatePath = CertificatePath,
            PrivateKeyPath = PrivateKeyPath,
            PrivateKeyPassword = PrivateKeyPassword,
            AutoGenerate = AutoGenerate,
            KeySize = KeySize,
            ValidityYears = ValidityYears
        };
    }
}
