using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;

namespace TinyUa.Security.Tests;

/// <summary>
/// In-process OPC Foundation (OPCF) secure server used as the "reference truth" for
/// validating TinyUa's security implementation. Exposes all three modern security
/// policies (Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss) plus None
/// on a single TCP base address, and supports Anonymous + UserName (test/user123).
///
/// The built-in <see cref="CoreNodeManager"/> (auto-created by <see cref="StandardServer"/>)
/// exposes the standard Server nodes — Objects (i=85), Server.ServerStatus.CurrentTime
/// (i=2258) — sufficient to validate Browse/Read/Subscribe without a custom address space.
///
/// Startup uses <see cref="ApplicationInstance"/> with a directory cert store so OPCF's own
/// certificate lifecycle (creation, validation, domain checking) is exercised exactly as a
/// real deployment — minimizing the chance that a fixture-config quirk is mistaken for a
/// TinyUa bug.
/// </summary>
public sealed class OpcfSecureServerFixture : IDisposable
{
    public const int Port = 48420;
    public string EndpointUrl => $"opc.tcp://localhost:{Port}";

    /// <summary>The server's certificate (populated after start, for diagnostics).</summary>
    public X509Certificate2? ServerCertificate { get; private set; }

    public const string UserName = "test";
    public const string UserPassword = "user123";

    private readonly TestServer _server;
    private readonly ApplicationInstance _app;
    private readonly string _certStorePath;

    public OpcfSecureServerFixture()
    {
        // Mirror OPCF trace to the test console so startup failures are diagnosable.
        // xUnit captures Console.Out into ITestOutputHelper when configured, and the
        // trace listener also helps when running `dotnet test` at the command line.
        Trace.Listeners.Add(new ConsoleTraceListener());

        // Per-run directory cert store under the temp folder. OPCF auto-creates a
        // self-signed cert here on first run and reuses it. Cleaning the directory
        // up front avoids stale-cert issues across runs.
        _certStorePath = Path.Combine(Path.GetTempPath(), $"TinyUaTestServer_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_certStorePath);

        var config = BuildConfiguration();

        _app = new ApplicationInstance
        {
            ApplicationName = "TinyUa Test Server",
            ApplicationType = ApplicationType.Server,
            ApplicationConfiguration = config,
            // Let ApplicationInstance create the server cert if it doesn't exist yet.
            DisableCertificateAutoCreation = false,
        };

        _server = new TestServer();
        try
        {
            // ApplicationInstance.Start(ServerBase) does NOT auto-create/load the instance
            // certificate — it just calls server.Start(config). The canonical OPCF pattern
            // (see NetCoreConsoleServer sample) is to call CheckApplicationInstanceCertificate
            // first, which loads the cert from the store or creates a self-signed one if
            // missing (DisableCertificateAutoCreation=false) and assigns it to
            // config.SecurityConfiguration.ApplicationCertificate.Certificate. Without this,
            // ServerBase.OnServerStarting throws "Server does not have an instance certificate
            // assigned" (StatusCode=0x80890000).
            bool certCreated = _app
                .CheckApplicationInstanceCertificate(silent: false, minimumKeySize: 2048)
                .GetAwaiter().GetResult();
            Trace.WriteLine($"[Fixture] CheckApplicationInstanceCertificate completed. CertCreated={certCreated}.");

            // Now start the server — OnServerStarting will find the cert already assigned.
            _app.Start(_server).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"OPCF server failed to start. EndpointUrl={EndpointUrl}, " +
                $"CertStorePath={_certStorePath}. " +
                $"Exception chain:{Environment.NewLine}{FormatExceptionChain(ex)}", ex);
        }

        // Capture the server cert for diagnostics (TinyUa discovers it itself via GetEndpoints).
        try
        {
            ServerCertificate = config.SecurityConfiguration.ApplicationCertificate.Certificate;
        }
        catch { /* non-fatal — only used for logging */ }
    }

    private ApplicationConfiguration BuildConfiguration()
    {
        var config = new ApplicationConfiguration
        {
            ApplicationName = "TinyUa Test Server",
            ApplicationUri = $"urn:localhost:tinyua:testsrv",
            ProductUri = "http://tinyua/testserver",
            ApplicationType = ApplicationType.Server,
            SecurityConfiguration = new SecurityConfiguration
            {
                // Directory store lets OPCF create + manage the server cert with proper
                // SAN/EKU and domain validation — the canonical deployment path.
                ApplicationCertificate = new CertificateIdentifier
                {
                    StoreType = CertificateStoreType.Directory,
                    StorePath = _certStorePath,
                    SubjectName = "CN=TinyUa Test Server, O=TinyUa, C=US",
                },
                // Empty trusted stores + auto-accept so self-signed test certs work.
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
                BaseAddresses = { EndpointUrl },
                SecurityPolicies =
                {
                    new ServerSecurityPolicy { SecurityMode = MessageSecurityMode.None,             SecurityPolicyUri = SecurityPolicies.None },
                    new ServerSecurityPolicy { SecurityMode = MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Basic256Sha256 },
                    new ServerSecurityPolicy { SecurityMode = MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Aes128_Sha256_RsaOaep },
                    new ServerSecurityPolicy { SecurityMode = MessageSecurityMode.SignAndEncrypt,   SecurityPolicyUri = SecurityPolicies.Aes256_Sha256_RsaPss },
                },
                UserTokenPolicies =
                {
                    new UserTokenPolicy(UserTokenType.Anonymous) { PolicyId = "Anonymous" },
                    new UserTokenPolicy(UserTokenType.UserName)  { PolicyId = "UserName" },
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
                TraceMasks = -1, // verbose — surfaces startup errors
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
        ServerCertificate?.Dispose();
        // Best-effort cleanup of the per-run cert store directory.
        try { Directory.Delete(_certStorePath, recursive: true); } catch { }
    }

    private static string FormatExceptionChain(Exception? ex)
    {
        var sb = new System.Text.StringBuilder();
        int depth = 0;
        while (ex != null)
        {
            sb.Append(new string(' ', depth * 2));
            sb.Append($"[{depth}] {ex.GetType().FullName}: {ex.Message}");
            if (ex is ServiceResultException sre)
            {
                sb.Append($" | StatusCode=0x{sre.StatusCode:X8}");
                if (sre.InnerResult != null)
                    sb.Append($" | InnerResult.StatusCode=0x{sre.InnerResult.StatusCode:X8}");
            }
            sb.AppendLine();
            ex = ex.InnerException;
            depth++;
        }
        return sb.ToString();
    }
}

/// <summary>
/// Minimal <see cref="StandardServer"/> subclass that intercepts user-token validation
/// via the <see cref="SessionManager.ImpersonateUser"/> event. Accepts the test
/// credentials; all other UserName credentials are rejected.
/// </summary>
internal sealed class TestServer : StandardServer
{
    protected override SessionManager CreateSessionManager(IServerInternal server, ApplicationConfiguration configuration)
    {
        var manager = base.CreateSessionManager(server, configuration);
        manager.ImpersonateUser += OnImpersonateUser;
        return manager;
    }

    // ImpersonateEventHandler signature is (Session session, ImpersonateEventArgs args).
    private static void OnImpersonateUser(Session session, ImpersonateEventArgs args)
    {
        if (args.NewIdentity is UserNameIdentityToken userNameToken)
        {
            string actualPassword;
            try
            {
                actualPassword = userNameToken.DecryptedPassword ?? string.Empty;
            }
            catch (Exception)
            {
                args.IdentityValidationError = ServiceResult.Create(
                    StatusCodes.BadIdentityTokenRejected,
                    "UserName password could not be decrypted.");
                return;
            }

            if (userNameToken.UserName == OpcfSecureServerFixture.UserName
                && actualPassword == OpcfSecureServerFixture.UserPassword)
            {
                args.Identity = new UserIdentity(userNameToken);
            }
            else
            {
                args.IdentityValidationError = ServiceResult.Create(
                    StatusCodes.BadIdentityTokenRejected,
                    "Unknown user name or bad password.");
            }
        }
    }
}
