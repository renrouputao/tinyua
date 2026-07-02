using System;
using System.IO;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace TinyUa.Security.Tests;

/// <summary>
/// Cross-check that the OPC Foundation's OWN client can connect to the same in-process
/// secure server. This isolates "the server fixture is misconfigured" from "TinyUa is broken":
///
///   - If this test FAILS but the fixture started → the OPCF server config is wrong (cert,
///     policy list, user-token policy). Fix the fixture, not TinyUa.
///   - If this test PASSES but <see cref="SecurityIntegrationTests"/> fails → the bug is in
///     TinyUa's security implementation. Use <c>SecurityDebugLogger</c> output to locate it.
///
/// This test uses the OPCF client with <c>useSecurity: true</c> so <c>CoreClientUtils.SelectEndpoint</c>
/// selects the most secure endpoint the server advertises (one of Basic256Sha256/Aes128/Aes256).
/// The OPCF client needs its OWN application certificate to do asymmetric SignAndEncrypt, so it
/// uses the same ApplicationInstance + directory cert store pattern as the server fixture.
/// </summary>
[Collection("SecureServer")]
public sealed class OpcfClientCrossCheckTests
{
    private readonly OpcfSecureServerFixture _fixture;
    private readonly ITestOutputHelper _output;

    public OpcfClientCrossCheckTests(OpcfSecureServerFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task OpcfClient_CanConnectToSameSecureServer()
    {
        // Per-run directory cert store for the client. ApplicationInstance creates a self-signed
        // cert on first call (DisableCertificateAutoCreation=false). Without this, Session.Create
        // throws "ApplicationCertificate cannot be found" because Session.LoadCertificate cannot
        // locate a cert from an empty CertificateIdentifier.
        var clientCertStorePath = Path.Combine(Path.GetTempPath(), $"TinyUaTestClient_{Guid.NewGuid():N}");
        Directory.CreateDirectory(clientCertStorePath);
        try
        {
            var appConfig = new ApplicationConfiguration
            {
                ApplicationName = "OPCF-CrossCheck-Client",
                ApplicationUri = $"urn:opcf:crosscheck:{Guid.NewGuid()}",
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = clientCertStorePath,
                        SubjectName = "CN=OPCF-CrossCheck-Client, O=TinyUa, C=US",
                    },
                    // Empty trusted stores + auto-accept so the server's self-signed cert is accepted.
                    TrustedIssuerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(clientCertStorePath, "trusted_issuers"),
                    },
                    TrustedPeerCertificates = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(clientCertStorePath, "trusted_peers"),
                    },
                    RejectedCertificateStore = new CertificateTrustList
                    {
                        StoreType = CertificateStoreType.Directory,
                        StorePath = Path.Combine(clientCertStorePath, "rejected"),
                    },
                    AutoAcceptUntrustedCertificates = true,
                    RejectSHA1SignedCertificates = false,
                    MinimumCertificateKeySize = 2048,
                },
                TransportQuotas = new TransportQuotas { OperationTimeout = 15000 },
                ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 60000 },
            };
            await appConfig.Validate(ApplicationType.Client);

            var clientApp = new ApplicationInstance
            {
                ApplicationName = "OPCF-CrossCheck-Client",
                ApplicationType = ApplicationType.Client,
                ApplicationConfiguration = appConfig,
                DisableCertificateAutoCreation = false,
            };
            bool certCreated = await clientApp
                .CheckApplicationInstanceCertificate(silent: false, minimumKeySize: 2048);
            _output.WriteLine($"OPCF client cert ready. CertCreated={certCreated}, " +
                $"Subject={appConfig.SecurityConfiguration.ApplicationCertificate.Certificate?.Subject}");

            // Select the most secure endpoint the server advertises via GetEndpoints.
            var endpoint = CoreClientUtils.SelectEndpoint(_fixture.EndpointUrl, useSecurity: true, discoverTimeout: 5000);
            Assert.NotNull(endpoint);
            Assert.NotEqual(MessageSecurityMode.None, endpoint.SecurityMode);
            _output.WriteLine($"OPCF client selected endpoint: {endpoint.EndpointUrl}, " +
                $"policy={endpoint.SecurityPolicyUri}, mode={endpoint.SecurityMode}");

            var cep = new ConfiguredEndpoint(null, endpoint, EndpointConfiguration.Create());

            using var session = await Session.Create(appConfig, cep, false, "CrossCheck",
                60000, new UserIdentity(new AnonymousIdentityToken()), null);

            Assert.NotNull(session.SessionId);
            _output.WriteLine($"OPCF client connected. SessionId={session.SessionId}");

            // Browse Objects (i=85) to confirm the address space is live.
            var refs = session.FetchReferences(new NodeId(85));
            Assert.NotNull(refs);
            Assert.True(refs.Count > 0, "OPCF client browse of Objects (i=85) returned no references.");
            _output.WriteLine($"OPCF client browsed i=85: {refs.Count} references.");
        }
        finally
        {
            try { Directory.Delete(clientCertStorePath, recursive: true); } catch { }
        }
    }
}
