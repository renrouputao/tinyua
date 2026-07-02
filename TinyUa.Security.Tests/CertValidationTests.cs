using System;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Configuration;
using TinyUa.Core.Security.Certificates;
using Xunit;
using Xunit.Abstractions;

namespace TinyUa.Security.Tests;

/// <summary>
/// Directly invokes the OPCF <c>CertificateValidator</c> (configured by the fixture with
/// <c>AutoAcceptUntrustedCertificates=true</c>) on a TinyUa-generated client certificate,
/// to determine whether the OPN failure (0x80130000 "Could not verify security on
/// OpenSecureChannel request") is caused by certificate validation.
///
/// The OPN server-side flow is:
///   ReadAsymmetricMessage → CertificateValidator.Validate(senderCertChain)
///   → if Validate throws, HandleCertificateValidationException wraps it as
///     BadCertificateInvalid (0x80100000) with the original error as InnerException
///   → ProcessOpenSecureChannelRequest catches it and routes to:
///     PATH A (line 330): "Could not verify security on OpenSecureChannel request."
///       triggered for: BadCertificateUntrusted, BadCertificateChainIncomplete,
///       BadCertificateRevoked, BadCertificateInvalid, BadCertificatePolicyCheckFailed
///     PATH B (line 335): different message (uses original status & message)
///       triggered for: BadCertificateHostNameInvalid, BadCertificateTimeInvalid,
///       BadCertificateUseNotAllowed, etc.
///     PATH C (line 339): "Could not verify security on OpenSecureChannel request." (fallback)
///
/// Since the OpnDecryptionTests proved decryption + signature + padding all work, the
/// failure must be in cert validation. This test pinpoints the EXACT validation error.
/// </summary>
[Collection("SecureServer")]
public sealed class CertValidationTests
{
    private readonly OpcfSecureServerFixture _fixture;
    private readonly ITestOutputHelper _output;

    public CertValidationTests(OpcfSecureServerFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public void ValidateTinyUaClientCert_WithFixtureValidator_ReportsExactError()
    {
        // ---- 1. Build a CertificateValidator from the fixture's SecurityConfiguration -
        // The fixture's ApplicationConfiguration.SecurityConfiguration has the same
        // trust/accept settings the server uses. We build an equivalent CertificateValidator
        // by calling Update(securityConfig), which is exactly what the OPCF server does
        // during startup (ApplicationInstance → CertificateValidator.Update).
        var config = typeof(OpcfSecureServerFixture)
            .GetField("_app", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.GetValue(_fixture) as ApplicationInstance;

        Assert.NotNull(config);
        var appConfig = config!.ApplicationConfiguration;
        _output.WriteLine($"[Step 1] Got ApplicationConfiguration. AppName={appConfig.ApplicationName}");
        _output.WriteLine($"[Step 1] AutoAcceptUntrustedCertificates: {appConfig.SecurityConfiguration.AutoAcceptUntrustedCertificates}");
        _output.WriteLine($"[Step 1] RejectSHA1SignedCertificates: {appConfig.SecurityConfiguration.RejectSHA1SignedCertificates}");
        _output.WriteLine($"[Step 1] MinimumCertificateKeySize: {appConfig.SecurityConfiguration.MinimumCertificateKeySize}");

        var validator = new Opc.Ua.CertificateValidator();
        validator.Update(appConfig.SecurityConfiguration).GetAwaiter().GetResult();
        // Set the application certificate so InternalValidateAsync can compare against it
        // (line 1005 of CertificateValidator.cs checks m_applicationCertificate).
        typeof(Opc.Ua.CertificateValidator)
            .GetField("m_applicationCertificate", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.SetValue(validator, appConfig.SecurityConfiguration.ApplicationCertificate.Certificate);
        _output.WriteLine($"[Step 1] Built CertificateValidator: {validator.GetType().FullName}");
        _output.WriteLine($"[Step 1] AppCert Subject: {appConfig.SecurityConfiguration.ApplicationCertificate.Certificate?.Subject}");

        // ---- 2. Generate a client cert (same path as UaClient) ------------------
        var (clientCert, clientRsaPriv) = CertificateGenerator.CreateSelfSigned(
            applicationName: "TinyUa-CertValidationTest",
            applicationUri: "urn:tinyua:certvalidation",
            keySize: 2048,
            validityYears: 1);
        using (clientRsaPriv) { }
        _output.WriteLine($"[Step 2] ClientCert Subject: {clientCert.Subject}");
        _output.WriteLine($"[Step 2] ClientCert Thumbprint: {clientCert.Thumbprint}");
        _output.WriteLine($"[Step 2] ClientCert HasPrivateKey: {clientCert.HasPrivateKey}");

        // Dump the cert's extensions so we can see what's actually on it.
        _output.WriteLine($"[Step 2] Cert extensions:");
        foreach (var ext in clientCert.Extensions)
        {
            _output.WriteLine($"  - {ext.GetType().Name}: {ext.Format(false)}");
        }

        // Specifically check the KeyUsage flags.
        var keyUsage = clientCert.Extensions.FindExtension<X509KeyUsageExtension>();
        if (keyUsage != null)
        {
            _output.WriteLine($"[Step 2] KeyUsage flags: {keyUsage.KeyUsages}");
            _output.WriteLine($"  - DigitalSignature: {(keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0}");
            _output.WriteLine($"  - KeyEncipherment:   {(keyUsage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) != 0}");
            _output.WriteLine($"  - DataEncipherment:  {(keyUsage.KeyUsages & X509KeyUsageFlags.DataEncipherment) != 0}");
            _output.WriteLine($"  - KeyAgreement:      {(keyUsage.KeyUsages & X509KeyUsageFlags.KeyAgreement) != 0}");
        }

        // ---- 3. Call validator.Validate(clientCert) -----------------------------
        // This is EXACTLY what the OPCF server does in ReadAsymmetricMessage:
        //   certificateValidator.Validate(senderCertificateChain)
        // where senderCertificateChain is a collection containing just the client cert.
        var chain = new X509Certificate2Collection { clientCert };
        _output.WriteLine("");
        _output.WriteLine("[Step 3] Calling CertificateValidator.Validate(clientCert)...");

        try
        {
            validator!.Validate(chain);
            _output.WriteLine("[Step 3] VALIDATE SUCCEEDED — cert was accepted.");
            _output.WriteLine("  This means cert validation is NOT the cause of the OPN failure.");
            _output.WriteLine("  The bug must be in signature/padding/decryption after all (re-check OpnDecryptionTests).");
        }
        catch (ServiceResultException sre)
        {
            _output.WriteLine($"[Step 3] VALIDATE THREW ServiceResultException:");
            _output.WriteLine($"  StatusCode: 0x{sre.StatusCode:X8} ({sre.StatusCode})");
            _output.WriteLine($"  Message: {sre.Message}");
            _output.WriteLine($"  SymbolicId: {sre.SymbolicId}");
            _output.WriteLine($"  AdditionalInfo: {sre.AdditionalInfo}");

            // Walk the InnerResult chain to see ALL errors
            _output.WriteLine("");
            _output.WriteLine("  Full InnerResult chain:");
            var result = sre.Result;
            int depth = 0;
            while (result != null)
            {
                _output.WriteLine($"    [{depth}] StatusCode=0x{result.Code:X8} ({result.Code})");
                _output.WriteLine($"        SymbolicId: {result.SymbolicId}");
                _output.WriteLine($"        LocalizedText: {result.LocalizedText}");
                _output.WriteLine($"        AdditionalInfo: {result.AdditionalInfo}");
                result = result.InnerResult;
                depth++;
            }

            // Check which PATH this would trigger in ProcessOpenSecureChannelRequest
            _output.WriteLine("");
            _output.WriteLine("  === Path analysis (ProcessOpenSecureChannelRequest) ===");

            // The validator's HandleCertificateValidationException wraps the original error
            // as BadCertificateInvalid (0x80100000) with the original as InnerException.
            // So ex.StatusCode = 0x80100000, ex.InnerException = original ServiceResultException.
            // ex2 = ex.InnerException, ex2.StatusCode = original error's StatusCode.
            uint ex2StatusCode = sre.StatusCode;
            if (sre.InnerException is ServiceResultException innerSre)
            {
                ex2StatusCode = innerSre.StatusCode;
                _output.WriteLine($"  ex.InnerException.StatusCode = 0x{ex2StatusCode:X8} ({ex2StatusCode})");
            }
            else
            {
                _output.WriteLine($"  ex.InnerException is NOT a ServiceResultException (it's {sre.InnerException?.GetType().Name ?? "null"})");
                _output.WriteLine($"  Using outer StatusCode for path analysis: 0x{ex2StatusCode:X8}");
            }

            // PATH A check
            bool pathA = ex2StatusCode == 2149187584u  // BadCertificateUntrusted
                      || ex2StatusCode == 2165112832u  // BadCertificateChainIncomplete
                      || ex2StatusCode == 2149384192u  // BadCertificateRevoked
                      || ex2StatusCode == 2148663296u  // BadCertificateInvalid
                      || ex2StatusCode == 2165571584u  // BadCertificatePolicyCheckFailed
                      || (sre.InnerResult != null && sre.InnerResult.StatusCode == 2149187584u);
            _output.WriteLine($"  PATH A (→ 'Could not verify security on OpenSecureChannel request.'): {pathA}");

            // PATH B check
            bool pathB = ex2StatusCode == 2148794368u  // BadCertificateHostNameInvalid
                      || ex2StatusCode == 2148859904u  // BadCertificateRevocationUnknown
                      || ex2StatusCode == 2148925440u  // BadCertificateTimeInvalid
                      || ex2StatusCode == 2148990976u
                      || ex2StatusCode == 2149056512u  // BadCertificateUseNotAllowed
                      || ex2StatusCode == 2149122048u
                      || ex2StatusCode == 2149253120u
                      || ex2StatusCode == 2149318656u
                      || ex2StatusCode == 2149449728u;
            _output.WriteLine($"  PATH B (→ different message with original status): {pathB}");

            bool pathC = !pathA && !pathB;
            _output.WriteLine($"  PATH C (→ 'Could not verify security on OpenSecureChannel request.' fallback): {pathC}");

            _output.WriteLine("");
            if (pathA || pathC)
            {
                _output.WriteLine("  >>> MATCH: This error produces 'Could not verify security on OpenSecureChannel request.' <<<");
            }
            else if (pathB)
            {
                _output.WriteLine("  >>> NO MATCH: This error would produce a DIFFERENT message.");
                _output.WriteLine("  >>> The OPN failure cause must be elsewhere.");
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine($"[Step 3] VALIDATE THREW {ex.GetType().FullName}: {ex.Message}");
        }
    }
}

/// <summary>
/// Extension helper to find a specific X509Extension type.
/// </summary>
internal static class X509ExtensionCollectionExtensions
{
    public static T? FindExtension<T>(this X509ExtensionCollection extensions) where T : X509Extension
    {
        foreach (var ext in extensions)
        {
            if (ext is T typed) return typed;
        }
        return null;
    }
}
