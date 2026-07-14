using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;
using TinyUa.Client;
using TinyUa.Client.Services;
using TinyUa.Core.Types;
using NodeId = TinyUa.Core.Types.NodeId;
using DataValue = TinyUa.Core.Types.DataValue;
using Variant = TinyUa.Core.Types.Variant;
using ReferenceDescription = TinyUa.Client.Services.ReferenceDescription;
using WriteValue = TinyUa.Client.Services.WriteValue;

namespace OpcUa.Example;

class Program
{
    // In-process selftest server port (kept stable across runs)
    const int SelfTestPort = 48440;
    const string SelfTestUrl = "opc.tcp://localhost:48440";

    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Default behaviour: start an in-process OPCF server and run every API example
        // against it. Pass a URL as the first argument to run against an external server.
        var externalUrl = args.Length > 0 ? args[0] : null;
        var useSelfTest = externalUrl == null || externalUrl.Equals("selftest", StringComparison.OrdinalIgnoreCase);

        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║   TinyUa — OPC UA Client API Examples    ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();

        TestServer? server = null;
        if (useSelfTest)
        {
            Console.WriteLine($"Starting in-process OPCF server on {SelfTestUrl} ...");
            server = new TestServer(SelfTestPort);
            Console.WriteLine("Server started. Security policies:");
            Console.WriteLine("  - None");
            Console.WriteLine("  - Basic256Sha256 (SignAndEncrypt)");
            Console.WriteLine("  - Aes128_Sha256_RsaOaep (SignAndEncrypt)");
            Console.WriteLine("  - Aes256_Sha256_RsaPss (SignAndEncrypt)");
            Console.WriteLine("  User tokens: Anonymous, UserName(test/user123)");
            Console.WriteLine();
        }
        var url = useSelfTest ? SelfTestUrl : externalUrl!;

        try
        {
            // ── Connection examples ──
            await Example_NoneSecurity(url);
            await Example_Basic256Sha256_Anonymous(url);
            await Example_Aes128_UserName(url);
            await Example_Aes256_Options(url);

            // ── Data access examples (over a secure channel) ──
            await Example_Read(url);
            await Example_Write(url);
            await Example_Browse(url);
            await Example_BrowseWithContinuation(url);

            // ── Subscription examples ──
            await Example_Subscription_Single(url);
            await Example_Subscription_Multiple(url);

            Console.WriteLine("All examples completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ FAILED: {ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"  Inner: {ex.InnerException.Message}");
        }
        finally
        {
            server?.Dispose();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Connection examples
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Example 0: None security — no encryption, anonymous user.
    /// Uses the fluent <c>ConnectTo(...).BuildAndRunAsync()</c> builder.
    /// </summary>
    static async Task Example_NoneSecurity(string url)
    {
        Console.WriteLine("── 0. None Security (no encryption, anonymous) ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    /// <summary>
    /// Example 1: Basic256Sha256 + Anonymous — the most common secure policy.
    /// OPN: RSA-PKCS1-SHA256, MSG: AES-256-CBC + HMAC-SHA256.
    /// Demonstrates <c>WithSecurity(policy)</c> + <c>WithSecurity(opts => ...)</c>
    /// to load a PFX client certificate.
    /// </summary>
    static async Task Example_Basic256Sha256_Anonymous(string url)
    {
        Console.WriteLine("── 1. Basic256Sha256 + Anonymous ──");
        Console.WriteLine("     (RSA-2048/PKCS1-SHA256 OPN, AES-256-CBC MSG, HMAC-SHA256)");

        var certFile = @"C:\Users\skyal\Desktop\tinyuacerts\TinyUa Client.pfx";
        await using var client = await UaClient
            .ConnectTo(url)
            .WithSecurity("Basic256Sha256")
            .WithSecurity(opts =>
            {
                opts.Certificate = new CertificateOptions
                {
                    CertificatePath = certFile,
                    AutoGenerate = false
                };
            })
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        var nodes = await client.BrowseAsync("i=85");
        Console.WriteLine($"  Objects folder: {nodes?.Length ?? 0} children");

        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    /// <summary>
    /// Example 2: Aes128_Sha256_RsaOaep + UserName.
    /// Password is RSA-OAEP encrypted before transmission.
    /// Demonstrates <c>WithAppName(...)</c> + <c>WithUserName(...)</c>.
    /// </summary>
    static async Task Example_Aes128_UserName(string url)
    {
        Console.WriteLine("── 2. Aes128_Sha256_RsaOaep + UserName ──");
        Console.WriteLine("     (RSA-OAEP-SHA1 OPN, AES-128-CBC MSG, RSA-OAEP password encryption)");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-A128")
            .WithSecurity("Aes128_Sha256_RsaOaep")
            .WithUserName("test", "user123")
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        var results = await client.ReadAsync(new NodeId[] { "i=2256", "i=2258" });
        if (results != null)
            for (int i = 0; i < results.Length; i++)
                Console.WriteLine($"  [{i}] = {results[i].DataValue?.Value?.Value ?? "(null)"}");
        Console.WriteLine();
    }

    /// <summary>
    /// Example 3: Aes256_Sha256_RsaPss using an explicit <see cref="UaClientOptions"/>
    /// object instead of the fluent builder.
    /// Demonstrates the constructor-style API: <c>new UaClient(url, options)</c> + <c>RunAsync()</c>.
    /// </summary>
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

        var root = await client.BrowseAsync("i=84");
        Console.WriteLine($"  Root folder: {root?.Length ?? 0} children");

        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  ServerTime: {time:HH:mm:ss.fff}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Read examples
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Example: Read API — single value via string NodeId, single via typed NodeId,
    /// batch read with StatusCode checks, and reading a non-Value attribute.
    /// </summary>
    static async Task Example_Read(string url)
    {
        Console.WriteLine("── Read API ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        // (a) Single value with implicit string-to-NodeId conversion
        var time = await client.ReadValueAsync<DateTime>("i=2258");
        Console.WriteLine($"  (a) ReadValueAsync<string>   ServerTime = {time:HH:mm:ss.fff}");

        // (b) Single value with typed NodeId + explicit AttributeId
        var state = await client.ReadValueAsync<int>(new NodeId(2259, 0));
        Console.WriteLine($"  (b) ReadValueAsync<int>      ServerStatus.State = {state} (0=Running)");

        // (c) Batch read — returns ReadResult[]? with per-node StatusCode
        NodeId[] nodes = { "i=2258", "i=2259", "i=2261", "i=99999" /* invalid */ };
        var batch = await client.ReadAsync(nodes);
        if (batch != null)
        {
            for (int i = 0; i < batch.Length; i++)
            {
                var r = batch[i];
                var v = r.DataValue?.Value?.Value;
                Console.WriteLine($"  (c) [{i}] NodeId={r.NodeId,-10} StatusCode={r.StatusCode,-30} value={v}");
            }
        }

        // (d) Low-level single ReadAsync returns ReadResult? with full DataValue
        var dv = await client.ReadAsync((NodeId)"i=2258");
        if (dv != null && dv.StatusCode.IsGood)
            Console.WriteLine($"  (d) ReadAsync(NodeId)        SourceTimestamp={dv.DataValue?.SourceTimestamp:O}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Write examples
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Example: Write API — single value via string NodeId, single via typed NodeId,
    /// and batch write with per-node StatusCode checks.
    /// </summary>
    static async Task Example_Write(string url)
    {
        Console.WriteLine("── Write API ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        // (a) Single write via string NodeId (read-only server node → BadUserAccessDenied)
        var w1 = await client.WriteAsync("i=2258", DateTime.UtcNow);
        Console.WriteLine($"  (a) WriteAsync(string,...)   StatusCode={w1?.StatusCode}");

        // (b) Single write via typed NodeId
        var w2 = await client.WriteAsync((NodeId)"i=2258", DateTime.UtcNow);
        Console.WriteLine($"  (b) WriteAsync(NodeId,...)   StatusCode={w2?.StatusCode}");

        // (c) Batch write — returns WriteResult[]? with per-node StatusCode
        var values = new WriteValue[]
        {
            new() { NodeId = "i=2258", Value = new DataValue(new Variant(DateTime.UtcNow)) },
            new() { NodeId = "i=2259", Value = new DataValue(new Variant(0)) },
            new() { NodeId = "i=2261", Value = new DataValue(new Variant("hello")) },
        };
        var batch = await client.WriteAsync(values);
        if (batch != null)
        {
            for (int i = 0; i < batch.Length; i++)
                Console.WriteLine($"  (c) [{i}] NodeId={batch[i].NodeId,-10} StatusCode={batch[i].StatusCode}");
        }

        // (d) WriteValueAsync<T> helper — fire-and-forget style (await still required)
        //     Note: writing to a server's read-only node returns BadUserAccessDenied,
        //     the round-trip itself is what's being demonstrated.
        await client.WriteValueAsync("i=2258", DateTime.UtcNow);
        Console.WriteLine($"  (d) WriteValueAsync<T>       completed (status ignored)");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Browse examples
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Example: Browse API — simple browse of Objects folder, iterate References,
    /// inspect NodeId / DisplayName / NodeClass / BrowseName.
    /// </summary>
    static async Task Example_Browse(string url)
    {
        Console.WriteLine("── Browse API ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        // Browse the Objects folder (i=85) — default: forward, max 100 refs
        var results = await client.BrowseAsync("i=85");
        if (results == null || results.Length == 0)
        {
            Console.WriteLine("  (no references returned)");
            Console.WriteLine();
            return;
        }

        var refs = results[0].References ?? Array.Empty<ReferenceDescription>();
        Console.WriteLine($"  Objects folder has {refs.Length} direct children:");
        foreach (var r in refs)
        {
            Console.WriteLine($"   - {r.NodeId,-20} {r.BrowseName?.Name,-25} ({r.NodeClass})");
            Console.WriteLine($"       DisplayName: {r.DisplayName?.Text}    TypeDef: {r.TypeDefinition}");
        }
        Console.WriteLine();
    }

    /// <summary>
    /// Example: Browse with continuation point — when a server returns fewer
    /// references than requested, call <c>BrowseNextAsync</c> with the
    /// continuation point to fetch the remaining ones.
    /// </summary>
    static async Task Example_BrowseWithContinuation(string url)
    {
        Console.WriteLine("── Browse with continuation point ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        // Request at most 3 references at a time to force a continuation point.
        var first = await client.BrowseAsync("i=85", maxReferences: 3);
        if (first == null || first.Length == 0)
        {
            Console.WriteLine("  (no references returned)");
            Console.WriteLine();
            return;
        }

        var firstRefs = first[0].References ?? Array.Empty<ReferenceDescription>();
        var totalFetched = firstRefs.Length;
        Console.WriteLine($"  First page: {firstRefs.Length} references");
        foreach (var r in firstRefs)
            Console.WriteLine($"   - {r.NodeId,-20} {r.DisplayName?.Text}");

        // If a continuation point was issued, keep paging until exhausted.
        var cp = first[0].ContinuationPoint;
        int pages = 1;
        while (cp != null && cp.Length > 0)
        {
            var next = await client.BrowseNextAsync(cp);
            if (next == null || next.Length == 0) break;

            var nextRefs = next[0].References ?? Array.Empty<ReferenceDescription>();
            totalFetched += nextRefs.Length;
            Console.WriteLine($"  Page #{++pages}: {nextRefs.Length} references");
            cp = next[0].ContinuationPoint;
        }

        Console.WriteLine($"  Total references fetched: {totalFetched}");
        Console.WriteLine();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Subscription examples
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Example: Subscribe to a single node — uses the convenience overload
    /// <c>SubscribeAsync&lt;T&gt;(nodeId, callback, interval)</c>.
    /// The returned <see cref="Subscription"/> is disposed to unsubscribe.
    /// </summary>
    static async Task Example_Subscription_Single(string url)
    {
        Console.WriteLine("── Subscription: single node ──");

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

    /// <summary>
    /// Example: Subscribe to multiple nodes in one subscription.
    /// Uses <c>SubscribeAsync(NodeId[], handler, interval)</c> — a single
    /// subscription is created and all nodes are monitored together.
    /// The <c>DataChangeHandler</c> delegate receives (nodeId, value, status).
    /// </summary>
    static async Task Example_Subscription_Multiple(string url)
    {
        Console.WriteLine("── Subscription: multiple nodes ──");

        await using var client = await UaClient
            .ConnectTo(url)
            .WithAppName("TinyUa-Example-SubMulti")
            .WithSecurity("Basic256Sha256")
            .BuildAndRunAsync();

        Console.WriteLine($"  Connected: {client.IsConnected}, Session: {client.SessionId}");

        NodeId[] nodes = { "i=2258", "i=2259" }; // CurrentTime, State
        var sub = await client.SubscribeAsync(
            nodes,
            (nodeId, value, status) =>
            {
                Console.WriteLine($"  [{nodeId}] value={value}  status={status}");
            },
            interval: 1000);

        await Task.Delay(3500);
        sub.Dispose();
        Console.WriteLine("  Disposed subscription");
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
            ApplicationType = Opc.Ua.ApplicationType.Server,
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
            ApplicationType = Opc.Ua.ApplicationType.Server,
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
                    new Opc.Ua.UserTokenPolicy(Opc.Ua.UserTokenType.Anonymous) { PolicyId = "Anonymous" },
                    new Opc.Ua.UserTokenPolicy(Opc.Ua.UserTokenType.UserName)  { PolicyId = "UserName" },
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
        config.Validate(Opc.Ua.ApplicationType.Server).GetAwaiter().GetResult();
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
