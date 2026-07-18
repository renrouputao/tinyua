# TinyUa

<p align="center">
  <strong>A lightweight, from-scratch OPC UA client stack for .NET 8</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://dotnet.microsoft.com/en-us/download/dotnet/8.0"><img src="https://img.shields.io/badge/.NET-8.0-512BD4.svg" alt=".NET 8"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
  <a href="https://www.nuget.org/packages/TinyUa.Client"><img src="https://img.shields.io/nuget/v/TinyUa.Client.svg" alt="NuGet"></a>
</p>

TinyUa implements the complete OPC UA binary protocol stack from scratch — binary encoding, four security policies, message chunking, secure channels, and a high-level client with a Fluent API. The core libraries have **zero dependency on the OPC Foundation SDK**. All cryptography uses only `System.Security.Cryptography` from .NET 8.

## Why TinyUa?

- **Zero OPCF SDK dependency** in core libraries — fully self-contained binary protocol implementation
- **Lightweight** — the core stack (Core + Transport + Client) has no external NuGet dependencies
- **Modern .NET** — targets .NET 8 with nullable reference types and async/await throughout
- **Fluent API** — intuitive builder pattern for connecting, configuring security, and executing operations
- **Comprehensive security** — 4 security policies, 3 user token types, auto-generated certificates, auto-discovery of server certificates
- **Production-ready features** — automatic reconnect with exponential backoff, bounded subscription dispatch with backpressure, keep-alive monitoring

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
| Basic256Sha256 | RSA-OAEP-SHA1 | AES-256-CBC + HMAC-SHA256 | RSA-SHA256 |
| Aes128Sha256RsaOaep | RSA-OAEP-SHA1 | AES-128-CBC + HMAC-SHA256 | RSA-SHA256 |
| Aes256Sha256RsaPss | RSA-OAEP-SHA256 | AES-256-CBC + HMAC-SHA256 | RSA-PSS-SHA256 |

**User identity tokens:** Anonymous, UserName, X509 Certificate

**Certificate management:**
- Auto-generated self-signed client certificates at runtime
- Auto-discovery of server certificates via GetEndpoints service
- Optional built-in server certificate validity, EKU, and chain-integrity validation
- DPAPI-encrypted credential persistence (WPF Explorer)

### Client

- **Fluent Builder API:** `UaClient.ConnectTo(url).WithSecurity(...).WithUserName(user, pass).BuildAndRunAsync()`
- **Services:** Read, Write, Browse, BrowseNext, CreateSession, ActivateSession, Subscribe, Publish
- **Subscriptions:** Session-level Publish credit window plus bounded, ordered per-subscription callback queues with configurable backpressure/drop policy
- **Reconnect:** Single-flight automatic reconnect with exponential backoff, session/subscription recovery, and keep-alive monitoring
- **State tracking:** `ClientState` events are emitted only for real state transitions; reconnect progress and subscription recovery have separate events
- **Error handling:** Configurable `ErrorMode` (Throw or ReturnNull)

### Tools

- **WPF Explorer** — Graphical OPC UA browser with security endpoint discovery and credential persistence
- **Console Example** — Self-test mode with in-process OPCF reference server
- **Benchmarks** — latency, security, live KEPServer correctness, subscription stress, and continuous memory/pool monitoring

## Quick Start

### Install via NuGet

TinyUa is available as three NuGet packages on [nuget.org](https://www.nuget.org/):

| Package | Description |
|---------|-------------|
| [`TinyUa.Client`](https://www.nuget.org/packages/TinyUa.Client) | Full OPC UA client — includes Core + Transport as transitive dependencies |
| [`TinyUa.Transport`](https://www.nuget.org/packages/TinyUa.Transport) | Message chunking and secure channel layer — depends on Core |
| [`TinyUa.Core`](https://www.nuget.org/packages/TinyUa.Core) | Binary encoding, type system, and security policies — zero external deps |

**For most users,** just install `TinyUa.Client` — it pulls in the other two automatically:

```bash
dotnet add package TinyUa.Client
```


### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build

```bash
git clone https://github.com/renrouputao/tinyua.git
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
using TinyUa.Client;

// Connect (no security, anonymous)
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithAppName("MyApp")
    .BuildAndRunAsync();

// Simple read
var time = await client.ReadValueAsync<DateTime>("i=2258");
Console.WriteLine($"ServerTime: {time:HH:mm:ss.fff}");

// Simple write
var result = await client.WriteAsync("ns=2;s=Demo.Static.Scalar.Double", 3.14);
Console.WriteLine(result?.StatusCode.IsGood == true
    ? "OK"
    : $"Failed: {result?.StatusCode.GetStatusText() ?? "no result"}");
```

```csharp
using TinyUa.Client;
using TinyUa.Core.Security;

// Connect with security and an existing PFX that contains its private key.
// Import the corresponding public certificate into the server's trusted-client store.
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithSecurity("Basic256Sha256")
    .WithSecurity(opts =>
    {
        opts.Certificate = new CertificateOptions
        {
            CertificatePath = @"D:\Certs\myclient.pfx",
            PrivateKeyPassword = "mypassword",   // optional
            AutoGenerate = false
        };
    })
    .BuildAndRunAsync();

var time = await client.ReadValueAsync<DateTime>("i=2258");
Console.WriteLine($"ServerTime: {time:HH:mm:ss.fff}");
```

To create and persist a certificate on first use, set `AutoGenerate = true` and point
`CertificatePath` at a writable `.pfx` path whose parent directory already exists. TinyUa also
writes a `.der` file next to it for importing into the server. Reuse the PFX on later connections.

```csharp
using TinyUa.Client;
using TinyUa.Core.Types;

// Connect with security + username
await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithAppName("MyApp")
    .WithSecurity("Basic256Sha256")
    .WithUserName("test", "user123")
    .BuildAndRunAsync();

// Batch read — each result carries its NodeId, StatusCode, and DataValue
var results = await client.ReadAsync(new NodeId[] { "i=2256", "i=2258" })
    ?? throw new InvalidOperationException("Read returned no results.");
foreach (var r in results)
{
    if (r.StatusCode.IsGood)
        Console.WriteLine($"  {r.NodeId} = {r.DataValue?.Value?.Value}");
    else
        Console.WriteLine($"  {r.NodeId}: {r.StatusCode.GetStatusText()}");
}
```

```csharp
using TinyUa.Client;
using TinyUa.Client.Services;
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
}) ?? throw new InvalidOperationException("Write returned no results.");
foreach (var r in writeResults)
{
    if (r.StatusCode.IsGood)
        Console.WriteLine($"  {r.NodeId}: OK");
    else
        Console.WriteLine($"  {r.NodeId}: {r.StatusCode.GetStatusText()}");
}
```

```csharp
using TinyUa.Client;
using TinyUa.Client.Subscriptions;

// Subscribe — typed callback (single node)
var sub = await client.SubscribeAsync<DateTime>("i=2258", val =>
{
    Console.WriteLine($"ServerTime: {val:HH:mm:ss.fff}");
}, interval: 500);

await Task.Delay(3000);
sub.Dispose();
```

```csharp
using TinyUa.Core.Types;

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

Subscription callbacks are serialized in arrival order within one subscription. Different
subscriptions have independent workers. Configure the bounded dispatch queue on the client:

```csharp
using TinyUa.Client;
using TinyUa.Client.Subscriptions;

await using var client = await UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithSubscriptionDispatch(options =>
    {
        options.QueueCapacity = 64; // queued Publish responses, not individual values
        options.OverflowPolicy = NotificationOverflowPolicy.Wait;
    })
    .BuildAndRunAsync();

var sub = await client.SubscribeAsync<double>(
    "ns=2;s=Demo.Dynamic.Scalar.Double",
    (value, status) => Console.WriteLine($"{status.GetStatusText()}: {value}"),
    interval: 100);

Console.WriteLine($"pending={sub.PendingNotificationMessages}, dropped={sub.DroppedNotificationMessages}");
```

`Wait` is the lossless default: a slow callback eventually slows the finite Publish-request
window. `DropOldest` favors fresh data and `DropNewest` preserves the existing backlog; both
increment `DroppedNotificationMessages`.

```csharp
// Browse — get child references from the Objects folder
var results = await client.BrowseAsync("i=85")
    ?? throw new InvalidOperationException("Browse returned no results.");
foreach (var desc in results[0].References ?? [])
    Console.WriteLine($"  {desc.DisplayName?.Text} ({desc.NodeClass}): {desc.NodeId}");

// BrowseNext — continue if there are more results
var continuationPoint = results[0].ContinuationPoint;
if (continuationPoint is { Length: > 0 })
{
    var next = await client.BrowseNextAsync(continuationPoint)
        ?? throw new InvalidOperationException("BrowseNext returned no results.");
    foreach (var desc in next[0].References ?? [])
        Console.WriteLine($"  {desc.DisplayName?.Text}: {desc.NodeId}");
}
```

For connection-state and subscription-recovery events, attach handlers before `RunAsync`:

```csharp
using TinyUa.Client;

await using var client = UaClient
    .ConnectTo("opc.tcp://myserver:4840")
    .WithReconnectRetries(-1)
    .Build();

client.StateChanged += state => Console.WriteLine($"state={state}");
client.ReconnectBackoff += (attempt, delayMs) =>
    Console.WriteLine($"reconnect attempt={attempt}, retry in {delayMs} ms");
client.SubscriptionsRecovered += lossless =>
    Console.WriteLine(lossless ? "subscriptions recovered losslessly" : "subscriptions rebuilt; data may be missing");

await client.RunAsync();
```

`StateChanged` is emitted only when the state actually changes. Concurrent socket and request
failure signals share one reconnect operation and do not produce duplicate
`Reconnecting` state notifications.

## Project Structure

| Project | Type | Description |
|---------|------|-------------|
| `TinyUa.Core` | Library | Binary encoding, OPC UA type system, 4 security policies, logging |
| `TinyUa.Transport` | Library | Message chunking, secure channel, key derivation (PSHA-256) |
| `TinyUa.Client` | Library | Fluent API, connection management, 10+ services, subscriptions, reconnect |
| `TinyUa.Example` | Console (.exe) | Self-test and example scenarios with in-process OPCF server |
| `TinyUa.Explorer` | WPF (.exe) | GUI browser with security endpoint discovery and certificate management |
| `TinyUa.CertGen` | WPF (.exe) | Client certificate generator |
| `TinyUa.Benchmarks` | Console | Latency, correctness, subscription stress, memory/GC, and crypto benchmarks |
| `TinyUa.Client.Tests` | xUnit | Client concurrency and robustness tests |
| `TinyUa.Security.Tests` | xUnit | Security integration tests against OPCF reference server |

### Dependency Graph

```
TinyUa.Core  ─────────────  (zero external deps — pure .NET 8)
  ├─ TinyUa.CertGen      ──  (references Core)
  └─ TinyUa.Transport  ───  (references Core)
       └─ TinyUa.Client  ──  (references Transport)
            ├─ TinyUa.Example      (+ OPCF SDK for in-process server)
            ├─ TinyUa.Explorer     (+ WPF, CommunityToolkit.Mvvm, WPF-UI)
            ├─ TinyUa.Benchmarks   (+ BenchmarkDotNet)
            ├─ TinyUa.Client.Tests
            └─ TinyUa.Security.Tests (+ OPCF SDK)
```

The OPC Foundation SDK (`OPCFoundation.NetStandard.Opc.Ua`) is used **only by `TinyUa.Example` and `TinyUa.Security.Tests`** to host an in-process reference server. Core, Transport, Client, Explorer, CertGen, Client.Tests, and Benchmarks do not depend on it.

## Configuration

```csharp
using TinyUa.Client;
using TinyUa.Client.Subscriptions;
using TinyUa.Core.Security;

var options = new UaClientOptions
{
    ApplicationName = "MyApp",
    Timeout = 30000,              // request timeout in ms
    SessionTimeout = 3600000,     // session lifetime in ms
    SessionKeepAliveIntervalMs = 0, // 0 = automatic idle heartbeat; negative = disabled
    ChannelLifetime = 3600000,    // secure channel lifetime in ms
    WarmupOnConnect = true,       // warm up the Read codec path after connecting
    MaxMessageSize = 0,           // 0 = use server default

    Security = new SecurityOptions
    {
        Policy = "Basic256Sha256",                  // None, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss
        Mode = MessageSecurityMode.SignAndEncrypt,  // None, Sign, SignAndEncrypt
        AutoDiscoverServerCertificate = true,       // auto-discover via GetEndpoints
        // false validates dates, EKU and chain integrity. Unknown self-signed roots are still
        // allowed and CRL revocation is not checked, so deploy an external trust/pinning policy
        // when your environment requires strict server identity verification.
        AutoAcceptServerCertificate = false,
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

    MaxPublishRequests = 2,          // finite session-level Publish credit window
    SubscriptionDispatch = new SubscriptionDispatchOptions
    {
        QueueCapacity = 64,
        OverflowPolicy = NotificationOverflowPolicy.Wait
    },

    ErrorMode = ErrorMode.Throw      // Throw or ReturnNull
};
```

## Live Verification and Diagnostics

The live-server commands default to `opc.tcp://localhost:49320`; pass another URL as the final
argument when needed:

```bash
# Connection, Browse, batch Read/Write, writable DemoCH/Data tags, and backpressure correctness
dotnet run --project TinyUa.Benchmarks -- none opc.tcp://localhost:49320

# Fast and slow subscription callback stress
dotnet run --project TinyUa.Benchmarks -- substress opc.tcp://localhost:49320

# Continuous DemoCH/Data batch Read/Write with allocation, GC, ArrayPool, and encoder-pool telemetry
# Runs until Ctrl+C
dotnet run --project TinyUa.Benchmarks -- memory opc.tcp://localhost:49320

# General throughput benchmark
dotnet run --project TinyUa.Benchmarks -- basic opc.tcp://localhost:49320

# Cryptographic primitive benchmarks (no server required)
dotnet run --project TinyUa.Benchmarks -- security
```

## Logging

Choose one logging configuration when building the client.

```csharp
using TinyUa.Client;
using TinyUa.Core.Logging;

// Console logging via delegate
await using var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .EnableLog((level, ex, msg) => Console.WriteLine($"[{level}] {msg}"))
    .BuildAndRunAsync();
```

```csharp
using TinyUa.Client;
using TinyUa.Core.Logging;

// Custom ILogger implementation
await using var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .WithLogger(new DelegateLogger((level, ex, msg) =>
        Console.WriteLine($"[{level}] {msg}"), LogLevel.Debug))
    .BuildAndRunAsync();
```

```csharp
using TinyUa.Client;
using TinyUa.Core.Logging;

// File logging (directory path, auto-creates log files)
await using var client = await UaClient.ConnectTo("opc.tcp://server:4840")
    .EnableLogFile("./logs", LogLevel.Debug, async: true)
    .BuildAndRunAsync();
```

## Documentation

- [Architecture and Refactoring Report](docs/refactoring-report.md) — Codebase architecture and robustness review (Chinese)
- [Contributing Guide](CONTRIBUTING.md) — Build, test, and PR instructions

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- The OPC Foundation for the OPC UA protocol specification
