# TinyUa — Agent Context

Build and operational instructions for AI coding agents working on this codebase.

## Build & Test

```bash
dotnet build TinyUa.sln
dotnet test
dotnet run --project TinyUa.Example -- selftest
```

## Architecture

```
TinyUa.Core  (no external deps, net8.0)
  ^-- TinyUa.Transport  (references Core)
        ^-- TinyUa.Client  (references Transport)
              ^-- TinyUa.Example  (Console, + OPCF SDK for in-process server)
              ^-- TinyUa.Explorer  (WPF, net8.0-windows, + CommunityToolkit.Mvvm + WPF-UI)
              ^-- TinyUa.Benchmarks  (+ BenchmarkDotNet)
              ^-- TinyUa.Client.Tests  (xUnit)
              ^-- TinyUa.Security.Tests  (xUnit, + OPCF SDK)
```

**Core libraries** (Core / Transport / Client) have **zero dependency on the OPC Foundation SDK**. All binary encoding, security, and protocols are implemented from scratch using .NET 8 `System.Security.Cryptography`.

The OPCF SDK (`OPCFoundation.NetStandard.Opc.Ua` v1.5.374.126) is used ONLY in Example and Security.Tests — for running an in-process reference server.

## Key Entry Points

- [TinyUa.Client/UaClient.cs](TinyUa.Client/UaClient.cs) — Main client entry point, `ClientState` enum, `ClientBuilder` with Fluent API
- [TinyUa.Client/UaClientOptions.cs](TinyUa.Client/UaClientOptions.cs) — All configuration: `SecurityOptions`, `UserIdentityOptions`, `CertificateOptions`, reconnect, timeout
- [TinyUa.Core/Security/SecurityPolicyFactory.cs](TinyUa.Core/Security/SecurityPolicyFactory.cs) — Creates security policies from string names
- [TinyUa.Core/Security/SecurityPolicy.cs](TinyUa.Core/Security/SecurityPolicy.cs) — `MessageSecurityMode` enum (public), `SecurityPolicy` abstract class (internal)
- [TinyUa.Transport/MessageChunk.cs](TinyUa.Transport/MessageChunk.cs) — OPC UA Part 6 message chunking: sign-then-encrypt / verify-before-decrypt pipeline
- [TinyUa.Transport/SecureConnection.cs](TinyUa.Transport/SecureConnection.cs) — Secure channel with token rotation state machine
- [TinyUa.Core/Types/Variant.cs](TinyUa.Core/Types/Variant.cs) — OPC UA variant type system with `GuessType()` inference
- [TinyUa.Example/Program.cs](TinyUa.Example/Program.cs) — Runnable examples and self-test entry point

## Engineering Conventions

- **InternalsVisibleTo chain**: Core → Transport → Client → {Tests, Benchmarks}
- **Nullability**: enabled project-wide; `ImplicitUsings` enabled in Core/Client, disabled in Transport
- **Variant type inference**: Use `Variant.GuessType()` to infer UA type from CLR type — do not construct Variant with raw type IDs directly
- **Security policy names**: Use short names in `SecurityOptions.Policy` — "None", "Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"
- **Certificate discovery**: `UaClient` auto-discovers server certificate via GetEndpoints service on connect (controlled by `AutoDiscoverServerCertificate`)
- **OPN vs MSG**: OpenSecureChannel (OPN) messages always use SignAndEncrypt; regular MSG messages use the configured `MessageSecurityMode`
- **Token rotation**: `SecureConnection` maintains current/next/previous `ChannelSecurityToken` instances; `SetChannel()` drives Issue/Renew transitions
- **No directives**: No `#region` / `#if` / `#pragma` in the codebase
- **Fluent Builder pattern**: `UaClient.ConnectTo(url).WithSecurity(...).BuildAndRunAsync()`

## Namespace Map

| Namespace | Project |
|-----------|---------|
| `TinyUa.Core` | Core (IEncodable, IDecodable interfaces) |
| `TinyUa.Core.Binary` | Core (BinaryEncoder, BinaryDecoder, Codecs) |
| `TinyUa.Core.Types` | Core (NodeId, Variant, UaTypes) |
| `TinyUa.Core.Logging` | Core (ILogger, NullLogger, FileLogger) |
| `TinyUa.Core.Security` | Core (SecurityPolicy, SecurityPolicyFactory, UserIdentityToken) |
| `TinyUa.Core.Security.Certificates` | Core (CertificateGenerator, CertificateLoader, CertificateValidator) |
| `TinyUa.Core.Security.Cryptography` | Core (AesCryptography, RsaCryptography, PSha256) |
| `TinyUa.Core.Security.Policies` | Core (SecurityPolicyBase, concrete policies) |
| `TinyUa.Core.Transport` | Transport (MessageChunk, SecureConnection) |
| `TinyUa.Core.Client` | Client (UaClient, ClientBuilder, UaClientOptions) |
| `TinyUa.Core.Client.Connection` | Client (UaConnection, UaSocketClient, ReconnectEngine) |
| `TinyUa.Core.Client.Discovery` | Client (EndpointDiscoverer, DiscoveredEndpoint) |
| `TinyUa.Core.Client.Services` | Client (Read/Write/Browse/Session/Subscription services) |
| `TinyUa.Core.Client.Subscriptions` | Client (SubscriptionManager, SubscriptionRouter) |

## Testing

- **Security.Tests** starts an in-process OPCF server for integration tests
- **Client.Tests** focuses on concurrency and robustness
- **selftest mode**: `dotnet run --project TinyUa.Example -- selftest` runs a self-contained connectivity test
- Tests may require an OPC UA server on `opc.tcp://localhost:4840` depending on the test suite
