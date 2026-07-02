using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Client;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using Xunit;
using Xunit.Abstractions;

namespace TinyUa.Security.Tests;

/// <summary>
/// End-to-end security validation: TinyUa client connects to the in-process OPCF secure
/// server over each modern policy × each identity, then exercises Browse + Read.
///
/// These tests are the primary validation of the Phase 1-10 security implementation:
///   - OPN asymmetric handshake (cert exchange, RSA-OAEP encrypt, RSA sign)
///   - Symmetric key derivation (P_SHA256 with correct client/remote direction)
///   - MSG sign + encrypt + decrypt + verify round-trip
///   - CreateSession / ActivateSession (including ClientSignature)
///   - UserName password encryption (RSA-OAEP with server cert + server nonce)
///
/// If <see cref="OpcfClientCrossCheckTests"/> passes but these fail, the bug is in TinyUa.
/// </summary>
[Collection("SecureServer")]
public sealed class SecurityIntegrationTests
{
    private readonly OpcfSecureServerFixture _fixture;
    private readonly ITestOutputHelper _output;

    public SecurityIntegrationTests(OpcfSecureServerFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    /// <summary>
    /// Policy × identity matrix. The None+Anonymous case is a regression baseline ensuring
    /// the security work did not break the existing unsecured path.
    /// </summary>
    public static IEnumerable<object[]> PolicyIdentityMatrix => new[]
    {
        new object[] { "None",                  "Anonymous" },
        new object[] { "Basic256Sha256",        "Anonymous" },
        new object[] { "Basic256Sha256",        "UserName" },
        new object[] { "Aes128_Sha256_RsaOaep", "Anonymous" },
        new object[] { "Aes128_Sha256_RsaOaep", "UserName" },
        new object[] { "Aes256_Sha256_RsaPss",  "Anonymous" },
        new object[] { "Aes256_Sha256_RsaPss",  "UserName" },
    };

    [Theory]
    [MemberData(nameof(PolicyIdentityMatrix))]
    public async Task TinyUa_CanBrowseAndReadOverSecureChannel(string policy, string identity)
    {
        var logger = new DelegateLogger((level, ex, msg) =>
        {
            _output.WriteLine($"[{level}] {msg}" + (ex != null ? $" | {ex.GetType().Name}: {ex.Message}" : ""));
        }, LogLevel.Debug);

        var options = new UaClientOptions
        {
            ApplicationName = "TinyUa-SecurityTest",
            ApplicationUri = "urn:tinyua:securitytest",
            Timeout = 15000,
            // Fail fast on connect errors — no retries masking the real failure.
            ReconnectMaxRetries = 0,
            Security = new SecurityOptions
            {
                Policy = policy,
                Mode = policy == "None" ? MessageSecurityMode.None : MessageSecurityMode.SignAndEncrypt,
                AutoDiscoverServerCertificate = true,
                AutoAcceptServerCertificate = true,
                Certificate = new CertificateOptions { AutoGenerate = true, KeySize = 2048, ValidityYears = 1 },
                UserIdentity = BuildIdentity(identity),
            },
        };

        await using var client = new UaClient(_fixture.EndpointUrl, options, logger);
        client.DebugMode = true;

        // Act — connect through the full secure handshake.
        await client.RunAsync();

        // Browse the Objects folder (i=85) — validates MSG-layer sign/encrypt round-trip.
        var browseResults = await client.BrowseAsync(new NodeId(85));
        Assert.NotNull(browseResults);
        Assert.True(browseResults!.Length > 0, "Browse returned no result entries.");
        var refs = browseResults[0].References;
        Assert.NotNull(refs);
        Assert.True(refs!.Length > 0, "Browse of Objects (i=85) returned no references.");

        // Read Server.ServerStatus.CurrentTime (i=2258) — validates a second MSG round-trip.
        var dv = await client.ReadAsync(new NodeId(2258));
        Assert.NotNull(dv);
        Assert.True(dv!.StatusCode?.IsGood == true,
            $"Read of i=2258 returned status {dv.StatusCode}");

        _output.WriteLine($"PASS: policy={policy}, identity={identity}, references={refs.Length}");
    }

    private static UserIdentityOptions BuildIdentity(string identity) => identity switch
    {
        "UserName" => new UserIdentityOptions
        {
            Type = UserTokenType.UserName,
            Username = OpcfSecureServerFixture.UserName,
            Password = OpcfSecureServerFixture.UserPassword,
        },
        _ => new UserIdentityOptions { Type = UserTokenType.Anonymous },
    };
}
