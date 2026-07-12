# TinyUa

<p align="center">
  <strong>A lightweight, from-scratch OPC UA client stack for .NET 8</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://dotnet.microsoft.com/en-us/download/dotnet/8.0"><img src="https://img.shields.io/badge/.NET-8.0-512BD4.svg" alt=".NET 8"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</p>

TinyUa implements the complete OPC UA binary protocol stack from scratch — binary encoding, four security policies, message chunking, secure channels, and a high-level client with a Fluent API. The core libraries have **zero dependency on the OPC Foundation SDK**. All cryptography uses only `System.Security.Cryptography` from .NET 8.

## Why TinyUa?

- **Zero OPCF SDK dependency** in core libraries — fully self-contained binary protocol implementation
- **Lightweight** — the core stack (Core + Transport + Client) has no external NuGet dependencies
- **Modern .NET** — targets .NET 8 with nullable reference types and async/await throughout
- **Fluent API** — intuitive builder pattern for connecting, configuring security, and executing operations
- **Comprehensive security** — 4 security policies, 3 user token types, auto-generated certificates, auto-discovery of server certificates
- **Production-ready features** — automatic reconnect with exponential backoff, subscriptions with credit-based flow control, keep-alive monitoring

## Features

### Protocol (from scratch — OPC UA Part 6 binary protocol)

- Binary encoding/decoding of all OPC UA built-in types
- Message chunking with sign-then-encrypt / verify-before-decrypt pipeline
- Secure channel lifecycle management (Open/Renew/Close)
- Token rotation with current/next/previous `ChannelSecurityToken` tracking
- PSHA-256 key derivation for symmetric channel keys

### Security

| Policy | Key Transport | Symmetric | Asymmetric Signature |
|--------|--------------|-----------|---------------------|
| None | — | — | — |
| Basic256Sha256 | RSA-OAEP-SHA256 | AES-256-CBC + HMAC-SHA256 | RSA-SHA256 |
| Aes128Sha256RsaOaep | RSA-OAEP-SHA256 | AES-128-CBC + HMAC-SHA256 | RSA-SHA256 |
| Aes256Sha256RsaPss | RSA-OAEP-SHA256 | AES-256-CBC + HMAC-SHA256 | RSA-PSS-SHA256 |

**User identity tokens:** Anonymous, UserName, X509 Certificate

**Certificate management:**
- Auto-generated self-signed client certificates at runtime
- Auto-discovery of server certificates via GetEndpoints service
- Custom certificate validation callbacks
- DPAPI-encrypted credential persistence (WPF Explorer)

### Client

- **Fluent Builder API:** `UaClient.ConnectTo(url).WithSecurity(...).WithUserName(user, pass).BuildAndRunAsync()`
- **Services:** Read, Write, Browse, BrowseNext, CreateSession, ActivateSession, Subscribe, Publish
- **Subscriptions:** Credit-based flow control (PublishRequest/PublishResponse model), configurable sampling/publishing intervals
- **Reconnect:** Automatic reconnect with exponential backoff, keep-alive monitoring
- **State tracking:** `ClientState` enum (Disconnected → Connecting → Connected → Reconnecting → Disconnecting)
- **Error handling:** Configurable `ErrorMode` (Throw or ReturnNull)

### Tools

- **WPF Explorer** — Graphical OPC UA browser with security endpoint discovery and credential persistence
- **Console Example** — Self-test mode with in-process OPCF reference server
- **Benchmarks** — BenchmarkDotNet-based performance and crypto primitive benchmarks

## Quick Start

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build

```bash
git clone https://github.com/YOUR_USER/tinyua.git
cd tinyua
dotnet build TinyUa.sln
```

### Run the self-test

```bash
dotnet run --project TinyUa.Example -- selftest
```

This starts an in-process OPC UA server and runs the client against it — no external server needed.

### Minimal code example

```csharp
using TinyUa.Core.Client;

// Connect (no security, anonymous)
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithAppName("MyApp")
    .BuildAndRunAsync();

// Simple read
var time = await client.ReadValueAsync<DateTime>("i=2258");
Console.WriteLine($"ServerTime: {time:HH:mm:ss.fff}");

// Simple write
var status = await client.WriteAsync("ns=2;s=Demo.Static.Scalar.Double", 3.14);
Console.WriteLine(status?.StatusCode.IsGood == true ? "OK" : $"Failed: {status?.StatusCode.GetStatusText()}");
```

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Security;

// Connect with security + fixed certificate
// First run: auto-generates cert if it doesn't exist (saves .pfx + .der)
// Import the .der into the server's Trusted Client list
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithSecurity("Basic256Sha256")
    .WithSecurity(opts =>
    {
        opts.Certificate = new CertificateOptions
        {
            CertificatePath = @"D:\Certs\myclient.pfx",
            PrivateKeyPassword = "mypassword",   // optional
            AutoGenerate = false                  // create 
        };
    })
    .BuildAndRunAsync();

var time = await client.ReadValueAsync<DateTime>("i=2258");
Console.WriteLine($"ServerTime: {time:HH:mm:ss.fff}");
```

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Types;

// Connect with security + username
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithAppName("MyApp")
    .WithSecurity("Basic256Sha256")
    .WithUserName("test", "user123")
    .BuildAndRunAsync();

// Batch read — each result carries its NodeId, StatusCode, and DataValue
var results = await client.ReadAsync(new NodeId[] { "i=2256", "i=2258" });
foreach (var r in results)
{
    if (r.StatusCode.IsGood)
        Console.WriteLine($"  {r.NodeId} = {r.DataValue?.Value?.Value}");
    else
        Console.WriteLine($"  {r.NodeId}: {r.StatusCode.GetStatusText()}");
}
```

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Client.Services;
using TinyUa.Core.Types;

// Batch write — each result carries its NodeId and StatusCode
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .BuildAndRunAsync();

var writeResults = await client.WriteAsync(new WriteValue[]
{
    new() { NodeId = "ns=2;s=Demo.Static.Scalar.Double", Value = new DataValue(3.14) },
    new() { NodeId = "ns=2;s=Demo.Static.Scalar.Float",  Value = new DataValue(2.718f) },
    new() { NodeId = "ns=2;s=Demo.Static.Scalar.Int32",  Value = new DataValue(42) },
});
foreach (var r in writeResults)
{
    if (r.StatusCode.IsGood)
        Console.WriteLine($"  {r.NodeId}: OK");
    else
        Console.WriteLine($"  {r.NodeId}: {r.StatusCode.GetStatusText()}");
}
```

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Client.Subscriptions;

// Subscribe — typed callback (single node)
var sub = await client.SubscribeAsync<DateTime>("i=2258", val =>
{
    Console.WriteLine($"ServerTime: {val:HH:mm:ss.fff}");
}, interval: 500);

await Task.Delay(3000);
sub.Dispose();
```

```csharp
// Subscribe — batch with NodeId in callback
var sub = await client.SubscribeAsync(
    new NodeId[] { "i=2258", "ns=2;s=Demo.Dynamic.Scalar.Double" },
    (nodeId, value, status) =>
    {
        if (status.IsGood)
            Console.WriteLine($"{nodeId}: {value}");
    },
    interval: 500);

await Task.Delay(3000);
sub.Dispose();
```

```csharp
// Browse — get child references from the Objects folder
var results = await client.BrowseAsync("i=85");
foreach (var desc in results[0].References)
    Console.WriteLine($"  {desc.DisplayName?.Text} ({desc.NodeClass}): {desc.NodeId}");

// BrowseNext — continue if there are more results
if (results[0].ContinuationPoint != null)
{
    var next = await client.BrowseNextAsync(results[0].ContinuationPoint);
    foreach (var desc in next[0].References)
        Console.WriteLine($"  {desc.DisplayName?.Text}: {desc.NodeId}");
}
```

## Project Structure

| Project | Type | Description |
|---------|------|-------------|
| `TinyUa.Core` | Library | Binary encoding, OPC UA type system, 4 security policies, logging |
| `TinyUa.Transport` | Library | Message chunking, secure channel, key derivation (PSHA-256) |
| `TinyUa.Client` | Library | Fluent API, connection management, 10+ services, subscriptions, reconnect |
| `TinyUa.Example` | Console (.exe) | Self-test and example scenarios with in-process OPCF server |
| `TinyUa.Explorer` | WPF (.exe) | GUI browser with security endpoint discovery and certificate management |
| `TinyUa.Benchmarks` | Console | BenchmarkDotNet performance and crypto primitive benchmarks |
| `TinyUa.Client.Tests` | xUnit | Client concurrency and robustness tests |
| `TinyUa.Security.Tests` | xUnit | Security integration tests against OPCF reference server |

### Dependency Graph

```
TinyUa.Core  ─────────────  (zero external deps — pure .NET 8)
  └─ TinyUa.Transport  ───  (references Core)
       └─ TinyUa.Client  ──  (references Transport)
            ├─ TinyUa.Example      (+ OPCF SDK for in-process server)
            ├─ TinyUa.Explorer     (+ WPF, CommunityToolkit.Mvvm, WPF-UI)
            ├─ TinyUa.Benchmarks   (+ BenchmarkDotNet)
            ├─ TinyUa.Client.Tests
            └─ TinyUa.Security.Tests (+ OPCF SDK)
```

The OPC Foundation SDK (`OPCFoundation.NetStandard.Opc.Ua`) is used **only in test and example projects** for reference comparisons. The core libraries and benchmarks are fully self-contained.

## Configuration

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Security;

var options = new UaClientOptions
{
    ApplicationName = "MyApp",
    Timeout = 30000,              // request timeout in ms
    SessionTimeout = 3600000,     // session lifetime in ms
    ChannelLifetime = 3600000,    // secure channel lifetime in ms
    MaxMessageSize = 0,           // 0 = use server default

    Security = new SecurityOptions
    {
        Policy = "Basic256Sha256",                  // None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss
        Mode = MessageSecurityMode.SignAndEncrypt,  // None, Sign, SignAndEncrypt
        AutoDiscoverServerCertificate = true,       // auto-discover via GetEndpoints
        AutoAcceptServerCertificate = true,         // auto-trust (disable in production for custom validation)
        UserIdentity = new UserIdentityOptions
        {
            Type = UserTokenType.UserName,
            Username = "user",
            Password = "pass"
        },
        Certificate = new CertificateOptions
        {
            AutoGenerate = true,
            KeySize = 2048,
            ValidityYears = 5
        }
    },

    ReconnectMaxRetries = -1,        // -1 = unlimited
    ReconnectInitialDelayMs = 1000,  // start with 1s delay
    ReconnectMaxDelayMs = 30000,     // cap at 30s (exponential backoff)

    ErrorMode = ErrorMode.Throw      // Throw or ReturnNull
};
```

## Logging

```csharp
using TinyUa.Core.Client;
using TinyUa.Core.Logging;

// Console logging via delegate
var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .EnableLog((level, ex, msg) => Console.WriteLine($"[{level}] {msg}"))
    .BuildAndRunAsync();

// Custom ILogger implementation
var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .WithLogger(new DelegateLogger((level, ex, msg) =>
        Console.WriteLine($"[{level}] {msg}"), LogLevel.Debug))
    .BuildAndRunAsync();

// File logging (directory path, auto-creates log files)
var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .EnableLogFile("./logs", LogLevel.Debug, async: true)
    .BuildAndRunAsync();
```

## Documentation

- [Security User Guide](docs/security-user-guide.md) — Step-by-step security configuration (Chinese)
- [Subscription Internals](subscription.md) — Deep dive into OPC UA subscription mechanics (Chinese)
- [Contributing Guide](CONTRIBUTING.md) — Build, test, and PR instructions

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- The OPC Foundation for the OPC UA protocol specification
