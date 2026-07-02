using TinyUa.Core.Security;

namespace TinyUa.Core.Client
{

    public enum ErrorMode
    {

        Throw,

        ReturnNull
    }

    public class UaClientOptions
    {
        public string ApplicationName { get; set; } = "TinyUaClient";
        public string ApplicationUri { get; set; } = $"urn:tinyua:{Guid.NewGuid()}";
        public string ProductUri { get; set; } = "urn:openua:client";
        public uint Timeout { get; set; } = 30000;
        public double SessionTimeout { get; set; } = 3600000;
        public uint ChannelLifetime { get; set; } = 3600000;
        public uint MaxMessageSize { get; set; } = 0;

        public ErrorMode ErrorMode { get; set; } = ErrorMode.Throw;

        public int ReconnectMaxRetries { get; set; } = -1;
        public int ReconnectInitialDelayMs { get; set; } = 1000;
        public int ReconnectMaxDelayMs { get; set; } = 30000;

        public SecurityOptions Security { get; set; } = new();

        public static UaClientOptions Default => new();
    }

    public class SecurityOptions
    {
        public string Policy { get; set; } = "None";

        public MessageSecurityMode Mode { get; set; } = MessageSecurityMode.None;

        public UserIdentityOptions UserIdentity { get; set; } = new();

        public CertificateOptions Certificate { get; set; } = new();

        public bool AutoDiscoverServerCertificate { get; set; } = true;

        public bool AutoAcceptServerCertificate { get; set; } = true;
    }

    public class UserIdentityOptions
    {
        public UserTokenType Type { get; set; } = UserTokenType.Anonymous;

        public string? Username { get; set; }

        public string? Password { get; set; }

        public string? CertificatePath { get; set; }

        public string? PrivateKeyPath { get; set; }
    }

    public class CertificateOptions
    {
        public string? CertificatePath { get; set; }

        public string? PrivateKeyPath { get; set; }

        public string? PrivateKeyPassword { get; set; }

        public bool AutoGenerate { get; set; } = true;

        public int KeySize { get; set; } = 2048;

        public int ValidityYears { get; set; } = 5;
    }
}
