using TinyUa.Client;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Benchmarks;

// Read-only diagnostics; finite retries and no raw request dumps or credential output.
internal static class ConnectionDiagnostics
{
    internal static async Task RunAsync(string[] args)
    {
        if (args.Length == 0)
            throw new ArgumentException("Usage: diagnose <opc.tcp://host:port/path> [None|Basic256Sha256|...] [None|Sign|SignAndEncrypt]");
        var url = args[0];
        var policy = args.Length > 1 ? args[1] : "None";
        var mode = args.Length > 2 ? Enum.Parse<MessageSecurityMode>(args[2], true)
            : policy == "None" ? MessageSecurityMode.None : MessageSecurityMode.SignAndEncrypt;
        var stage = "Discovery/TCP";
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            stage = "Endpoint discovery (TCP/Hello/OPN/GetEndpoints)";
            var endpoints = await TinyUa.Client.Discovery.EndpointDiscoverer.DiscoverAsync(url, 5000, deadline.Token);
            foreach (var endpoint in endpoints)
                Console.WriteLine($"Endpoint: {endpoint.EndpointUrl}; {endpoint.DisplayText}");
            var logger = new DelegateLogger((level, error, message) =>
            {
                // Only allow handshake metadata from Debug; raw binary/security dumps may
                // contain credentials or key material and are deliberately excluded.
                if (message.StartsWith("Connect stage:", StringComparison.Ordinal))
                {
                    stage = message;
                    Console.WriteLine(message);
                }
                else if (level >= LogLevel.Warning || message.StartsWith("Hello acknowledged:", StringComparison.Ordinal) ||
                    message.StartsWith("Activating session:", StringComparison.Ordinal))
                    Console.WriteLine($"{level}: {message}");
            });
            var options = new UaClientOptions { Timeout = 5000, ReconnectMaxRetries = 0, WarmupOnConnect = false };
            options.Security.Policy = policy;
            options.Security.Mode = mode;
            var certificate = Environment.GetEnvironmentVariable("TINYUA_CLIENT_CERT");
            if (!string.IsNullOrEmpty(certificate))
                options.Security.Certificate = new CertificateOptions
                {
                    CertificatePath = certificate, AutoGenerate = false,
                    PrivateKeyPassword = Environment.GetEnvironmentVariable("TINYUA_CLIENT_CERT_PASSWORD")
                };
            var username = Environment.GetEnvironmentVariable("TINYUA_TEST_USERNAME");
            if (!string.IsNullOrEmpty(username))
                options.Security.UserIdentity = new UserIdentityOptions
                {
                    Type = UserTokenType.UserName, Username = username,
                    Password = Environment.GetEnvironmentVariable("TINYUA_TEST_PASSWORD")
                };
            Console.WriteLine($"Connecting: policy={policy}, mode={mode}, identity={options.Security.UserIdentity.Type}, retries=0");
            await using var client = new UaClient(url, options, logger);
            await client.RunAsync(deadline.Token);
            stage = "Read ServerStatus.State";
            var read = await client.ReadAsync(new NodeId(2259u), cancellationToken: deadline.Token);
            Console.WriteLine($"Connected={client.IsConnected}; StateRead={read?.StatusCode.GetStatusText()}");
        }
        catch (Exception error)
        {
            Console.WriteLine($"FAILED at {stage}");
            for (Exception? current = error; current != null; current = current.InnerException)
                Console.WriteLine($"  {current.GetType().Name}: {current.Message}");
            throw;
        }
    }
}
