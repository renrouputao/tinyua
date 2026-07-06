using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using TinyUa.Client;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using Xunit;
using Xunit.Abstractions;

namespace TinyUa.Security.Tests;

/// <summary>
/// Focused diagnostic test that captures ALL OPCF server trace output during a single
/// TinyUa OPN attempt, to reveal the exact server-side exception behind the generic
/// "Could not verify security on OpenSecureChannel request" (0x80130000) error.
///
/// The OPCF server logs via Utils.Trace → Trace.Listeners. This test adds a custom
/// listener that captures every line, then dumps the full trace after the attempt.
/// </summary>
[Collection("SecureServer")]
public sealed class OpnDiagnosticTests
{
    private readonly OpcfSecureServerFixture _fixture;
    private readonly ITestOutputHelper _output;

    public OpnDiagnosticTests(OpcfSecureServerFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task DiagnoseOpnFailure_Basic256Sha256_Anonymous()
    {
        // Capture ALL OPCF trace output in a thread-safe StringBuilder.
        var sb = new StringBuilder();
        var captureListener = new StringWriterTraceListener(sb);
        Trace.Listeners.Add(captureListener);
        try
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
                ReconnectMaxRetries = 0,
                Security = new SecurityOptions
                {
                    Policy = "Basic256Sha256",
                    Mode = MessageSecurityMode.SignAndEncrypt,
                    AutoDiscoverServerCertificate = true,
                    AutoAcceptServerCertificate = true,
                    Certificate = new CertificateOptions { AutoGenerate = true, KeySize = 2048, ValidityYears = 1 },
                    UserIdentity = new UserIdentityOptions { Type = UserTokenType.Anonymous },
                },
            };

            await using var client = new UaClient(_fixture.EndpointUrl, options, logger);
            client.DebugMode = true;

            Exception? caught = null;
            try
            {
                await client.RunAsync();
            }
            catch (Exception ex)
            {
                caught = ex;
                _output.WriteLine($"=== CLIENT EXCEPTION ===");
                _output.WriteLine($"Type: {ex.GetType().FullName}");
                _output.WriteLine($"Message: {ex.Message}");
                if (ex.InnerException != null)
                {
                    _output.WriteLine($"Inner: {ex.InnerException.GetType().FullName}: {ex.InnerException.Message}");
                }
            }

            // Dump ALL captured OPCF server trace.
            _output.WriteLine("");
            _output.WriteLine("========== OPCF SERVER TRACE ==========");
            var trace = sb.ToString();
            if (string.IsNullOrEmpty(trace))
            {
                _output.WriteLine("(no trace output captured)");
            }
            else
            {
                foreach (var line in trace.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                {
                    _output.WriteLine(line);
                }
            }
            _output.WriteLine("========== END OPCF TRACE ==========");
        }
        finally
        {
            Trace.Listeners.Remove(captureListener);
        }
    }

    /// <summary>
    /// Simple TraceListener that writes to a thread-safe StringBuilder.
    /// </summary>
    private sealed class StringWriterTraceListener : TraceListener
    {
        private readonly StringBuilder _sb;
        private readonly object _lock = new();

        public StringWriterTraceListener(StringBuilder sb) => _sb = sb;

        public override void Write(string? message)
        {
            lock (_lock) { _sb.Append(message); }
        }

        public override void WriteLine(string? message)
        {
            lock (_lock) { _sb.AppendLine(message); }
        }
    }
}
