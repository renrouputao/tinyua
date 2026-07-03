using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;
using TinyUa.Core.Client;
using NodeId = TinyUa.Core.Types.NodeId;

namespace OpcUa.Example;

class Program
{
    const string DefaultUrl = "opc.tcp://localhost:48010";

    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // ── selftest: start an in-process OPCF server and run all examples ──
        if (args.Length > 0 && args[0].Equals("selftest", StringComparison.OrdinalIgnoreCase))
        {
            await RunSelfTestAsync();
            return;
        }

        // ── Normal mode: connect to the given (or default) server ──
        var url = args.Length > 0 ? args[0] : DefaultUrl;

        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║   TinyUa — OPC UA Client Examples        ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();

        // Example 0: None security (the original default)
        await Example_NoneSecurity(url);

        // Example 1: Basic256Sha256 + Anonymous
        await Example_Basic256Sha256_Anonymous(url);

        // Example 2: Aes128_Sha256_RsaOaep + UserName
        await Example_Aes128_UserName(url);

        // Example 3: Aes256_Sha256_RsaPss + Anonymous (using options object)
        await Example_Aes256_Options(url);

        Console.WriteLine("All examples completed.");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Example 0: No security (None policy + Anonymous)
    // ═══════════════════════════════════════════════════════════════════════

    static async Task Example_NoneSecurity(string url)
    {
        Console.WriteLine("── 0. None Security (no encryption, anonymous) ──");
        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-None")
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");
        
        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Example 1: Basic256Sha256 + Anonymous — most common secure policy
    // ═══════════════════════════════════════════════════════════════════════

    static async Task Example_Basic256Sha256_Anonymous(string url)
    {
        Console.WriteLine("── 1. Basic256Sha256 + Anonymous ──");
        Console.WriteLine("     (RSA-2048/PKCS1-SHA256 OPN, AES-256-CBC MSG, HMAC-SHA256)");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-B256")
            .WithSecurity("Basic256Sha256")   // OPN: RSA-PKCS1-SHA256, MSG: AES-256 + HMAC-SHA256
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        // Browse the Objects folder
        var nodes = await client.BrowseAsync("i=85");
        Console.WriteLine($"  Objects folder: {nodes?.Length ?? 0} children");

        // Read Server.ServerStatus.CurrentTime
        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Example 2: Aes128_Sha256_RsaOaep + UserName — username auth with
    //             RSA-OAEP password encryption
    // ═══════════════════════════════════════════════════════════════════════

    static async Task Example_Aes128_UserName(string url)
    {
        Console.WriteLine("── 2. Aes128_Sha256_RsaOaep + UserName ──");
        Console.WriteLine("     (RSA-OAEP-SHA1 OPN, AES-128-CBC MSG, RSA-OAEP password encryption)");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-A128")
            .WithSecurity("Aes128_Sha256_RsaOaep")
            .WithUserName("test", "user123")   // password is RSA-OAEP encrypted before transmission
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        // Read multiple nodes
        var results = await client.ReadAsync(new NodeId[] { "i=2256", "i=2258" });
        if (results != null)
            for (int i = 0; i < results.Length; i++)
                Console.WriteLine($"  [{i}] = {results[i].DataValue?.Value?.Value ?? "(null)"}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Example 3: Aes256_Sha256_RsaPss + Anonymous — using explicit options
    //             object instead of the fluent builder
    // ═══════════════════════════════════════════════════════════════════════

    static async Task Example_Aes256_Options(string url)
    {
        Console.WriteLine("── 3. Aes256_Sha256_RsaPss + Anonymous (explicit options) ──");
        Console.WriteLine("     (RSA-PSS-SHA384 OPN, AES-256-CBC MSG, HMAC-SHA256)");

        var options = new UaClientOptions
        {
            ApplicationName = "TinyUa-Example-A256",
            Timeout = 15000,
            Security = new SecurityOptions
            {
                Policy = "Aes256_Sha256_RsaPss",
                AutoAcceptServerCertificate = true,
                Certificate = new CertificateOptions { AutoGenerate = true },
            },
        };

        await using var client = new UaClient(url, options);
        await client.RunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        // Browse + Read
        var root = await client.BrowseAsync("i=84");
        Console.WriteLine($"  Root folder: {root?.Length ?? 0} children");

        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Self-test: starts an in-process OPCF server and runs all examples
    //  against it. Usage: dotnet run --project TinyUa.Example -- selftest
    // ═══════════════════════════════════════════════════════════════════════

    static async Task RunSelfTestAsync()
    {
        const int port = 48440;
        var url = $"opc.tcp://localhost:{port}";

        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║   TinyUa — Security Self-Test            ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();
        Console.WriteLine($"Starting in-process OPCF server on {url} ...");

        using var server = new TestServer(port);
        Console.WriteLine("Server started. Security policies:");
        Console.WriteLine("  - None");
        Console.WriteLine("  - Basic256Sha256 (SignAndEncrypt)");
        Console.WriteLine("  - Aes128_Sha256_RsaOaep (SignAndEncrypt)");
        Console.WriteLine("  - Aes256_Sha256_RsaPss (SignAndEncrypt)");
        Console.WriteLine("  User tokens: Anonymous, UserName(test/user123)");
        Console.WriteLine();

        try
        {
            await Example_NoneSecurity(url);
            await Example_Basic256Sha256_Anonymous(url);
            await Example_Aes128_UserName(url);
            await Example_Aes256_Options(url);

            // Bonus: subscription over a secure channel
            await Example_SubscriptionSecure(url);

            Console.WriteLine("✓ All security examples passed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ FAILED: {ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"  Inner: {ex.InnerException.Message}");
        }
    }

    static async Task Example_SubscriptionSecure(string url)
    {
        Console.WriteLine("── 4. Subscription over Basic256Sha256 ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-Sub")
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        var count = 0;
        var sub = await client.SubscribeAsync<DateTime>("i=2258", val =>
        {
            var n = Interlocked.Increment(ref count);
            Console.WriteLine($"  #{n}: {val:HH:mm:ss.fff}");
        }, interval: 500);

        await Task.Delay(3000);
        sub.Dispose();
        Console.WriteLine($"  Received {count} notifications over secure channel");
        Console.WriteLine();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  In-process OPCF server for self-test (mirrors OpcfSecureServerFixture)
// ═══════════════════════════════════════════════════════════════════════════

internal sealed class TestServer : IDisposable
{
    private readonly ApplicationInstance _app;
    private readonly StandardServer _server;
    private readonly string _certStorePath;

    public TestServer(int port)
    {
        _certStorePath = Path.Combine(Path.GetTempPath(), $"TinyUaExampleServer_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_certStorePath);

        var config = BuildConfiguration(port);
        _app = new ApplicationInstance
        {
            ApplicationName = "TinyUa Example Server",
            ApplicationType = ApplicationType.Server,
            ApplicationConfiguration = config,
            DisableCertificateAutoCreation = false,
        };
        _server = new ExampleTestServer();

        _app.CheckApplicationInstanceCertificate(silent: false, minimumKeySize: 2048)
            .GetAwaiter().GetResult();
        _app.Start(_server).GetAwaiter().GetResult();
    }

    private ApplicationConfiguration BuildConfiguration(int port)
    {
        var url = $"opc.tcp://localhost:{port}";
        var config = new ApplicationConfiguration
        {
            ApplicationName = "TinyUa Example Server",
            ApplicationUri = $"urn:localhost:tinyua:examplesrv",
            ApplicationType = ApplicationType.Server,
            SecurityConfiguration = new SecurityConfiguration
            {
                ApplicationCertificate = new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = _certStorePath,
                    SubjectName = "CN=TinyUa Example Server, O=TinyUa, C=US",
                },
                TrustedIssuerCertificates = new CertificateTrustList
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(_certStorePath, "trusted_issuers"),
                },
                TrustedPeerCertificates = new CertificateTrustList
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(_certStorePath, "trusted_peers"),
                },
                RejectedCertificateStore = new CertificateTrustList
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = Path.Combine(_certStorePath, "rejected"),
                },
                AutoAcceptUntrustedCertificates = true,
                RejectSHA1SignedCertificates = false,
                MinimumCertificateKeySize = 2048,
            },
            ServerConfiguration = new ServerConfiguration
            {
                BaseAddresses = { url },
                SecurityPolicies =
                {
                    new ServerSecurityPolicy { SecurityMode = Opc.Ua.MessageSecurityMode.None,             SecurityPolicyUri = SecurityPolicies.None },
                    new ServerSecurityPolicy { SecurityMode = Opc.Ua.MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Basic256Sha256 },
                    new ServerSecurityPolicy { SecurityMode = Opc.Ua.MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Aes128_Sha256_RsaOaep },
                    new ServerSecurityPolicy { SecurityMode = Opc.Ua.MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Aes256_Sha256_RsaPss },
                },
                UserTokenPolicies =
                {
                    new UserTokenPolicy(Opc.Ua.UserTokenType.Anonymous) { PolicyId = "Anonymous" },
                    new UserTokenPolicy(Opc.Ua.UserTokenType.UserName)  { PolicyId = "UserName" },
                },
                MaxSessionCount = 100,
            },
            TransportQuotas = new TransportQuotas
            {
                OperationTimeout = 600000,
                ChannelLifetime = 600000,
                SecurityTokenLifetime = 3600000,
            },
            TraceConfiguration = new TraceConfiguration
            {
                TraceMasks = 0,
                DeleteOnLoad = true,
            },
        };
        config.Validate(ApplicationType.Server).GetAwaiter().GetResult();
        return config;
    }

    public void Dispose()
    {
        try { _app?.Stop(); } catch { }
        try { _server?.Dispose(); } catch { }
        try { Directory.Delete(_certStorePath, recursive: true); } catch { }
    }
}

internal sealed class ExampleTestServer : StandardServer
{
    protected override SessionManager CreateSessionManager(IServerInternal server, ApplicationConfiguration configuration)
    {
        var manager = base.CreateSessionManager(server, configuration);
        manager.ImpersonateUser += (_, args) =>
        {
            if (args.NewIdentity is UserNameIdentityToken token)
            {
                if (token.UserName == "test" && token.DecryptedPassword == "user123")
                    args.Identity = new UserIdentity(token);
                else
                    args.IdentityValidationError = ServiceResult.Create(
                        StatusCodes.BadIdentityTokenRejected, "Bad credentials.");
            }
        };
        return manager;
    }
}
