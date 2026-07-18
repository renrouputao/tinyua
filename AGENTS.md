# TinyUa — Agent Context

Build, architecture, and operational instructions for AI coding agents working on this codebase.

## Build & Test

```bash
dotnet build TinyUa.sln
dotnet test TinyUa.Client.Tests/TinyUa.Client.Tests.csproj
dotnet test TinyUa.Security.Tests/TinyUa.Security.Tests.csproj
dotnet run --project TinyUa.Example -- selftest
```

`TinyUa.Explorer` and `TinyUa.CertGen` are Windows WPF applications. When their Windows SDK or
NuGet dependencies are unavailable, validate library changes by building/testing Core, Transport,
Client, Client.Tests, Security.Tests, and Benchmarks individually.

Live KEPServer checks default to `opc.tcp://localhost:49320`:

```bash
dotnet run --project TinyUa.Benchmarks -- none
dotnet run --project TinyUa.Benchmarks -- substress
dotnet run --project TinyUa.Benchmarks -- memory
```

`memory` runs continuously until Ctrl+C. It batch-reads verified-writable variables below
`Objects/DemoCH/Data`, writes their just-read values back, and reports allocation, GC, ArrayPool,
and encoder-pool telemetry.

## Architecture

```
TinyUa.Core  (no external dependencies, net8.0)
  +-- TinyUa.CertGen  (WPF, net8.0-windows)
  +-- TinyUa.Transport  (references Core)
        +-- TinyUa.Client  (references Transport)
              +-- TinyUa.Example  (Console, + OPCF SDK for in-process server)
              +-- TinyUa.Explorer  (WPF, net8.0-windows, + MVVM/WPF-UI)
              +-- TinyUa.Benchmarks  (+ BenchmarkDotNet)
              +-- TinyUa.Client.Tests  (xUnit)
              +-- TinyUa.Security.Tests  (xUnit, + OPCF SDK)
```

Core, Transport, and Client have zero dependency on the OPC Foundation SDK. Binary encoding,
transport, security, sessions, services, subscriptions, and reconnection are implemented from
scratch using .NET 8 and `System.Security.Cryptography`.

The OPCF SDK (`OPCFoundation.NetStandard.Opc.Ua` v1.5.374.126) is used only by Example and
Security.Tests to host an in-process reference server.

## Key Entry Points

- [TinyUa.Client/UaClient.cs](TinyUa.Client/UaClient.cs) — Public client API, lifecycle events,
  Read/Write/Browse/Subscribe helpers, and the single reconnect entry point
- [TinyUa.Client/ClientBuilder.cs](TinyUa.Client/ClientBuilder.cs) — Fluent builder
- [TinyUa.Client/UaClientOptions.cs](TinyUa.Client/UaClientOptions.cs) — Client, reconnect,
  keep-alive, subscription-dispatch, identity, certificate, and security options
- [TinyUa.Client/ClientStateMachine.cs](TinyUa.Client/ClientStateMachine.cs) — Idempotent lifecycle
  state transitions; `Replay` is the explicit repeated-notification path
- [TinyUa.Client/Connection/ReconnectEngine.cs](TinyUa.Client/Connection/ReconnectEngine.cs) —
  Single-flight reconnect, session recovery, Republish, and subscription rebuild
- [TinyUa.Client/Connection/UaSocketClient.cs](TinyUa.Client/Connection/UaSocketClient.cs) —
  Buffered socket receive ring, request correlation, gather send, and connection-loss signal
- [TinyUa.Client/Services/ReadService.cs](TinyUa.Client/Services/ReadService.cs) — `ReadResult`,
  `ReadValueId`, Read request/response
- [TinyUa.Client/Services/WriteService.cs](TinyUa.Client/Services/WriteService.cs) — `WriteResult`,
  `WriteValue`, Write request/response
- [TinyUa.Client/Subscriptions/PublishEngine.cs](TinyUa.Client/Subscriptions/PublishEngine.cs) —
  Session-level finite Publish-request credit window
- [TinyUa.Client/Subscriptions/SubscriptionManager.cs](TinyUa.Client/Subscriptions/SubscriptionManager.cs) —
  `DataChangeHandler`, `DataChangeHandlerEx`, `Subscription`, ordered callback worker, queue metrics
- [TinyUa.Client/Subscriptions/SubscriptionDispatchOptions.cs](TinyUa.Client/Subscriptions/SubscriptionDispatchOptions.cs) —
  Queue capacity and `Wait`/`DropOldest`/`DropNewest` policy
- [TinyUa.Core/Binary/BufferLease.cs](TinyUa.Core/Binary/BufferLease.cs) — Class-based ArrayPool
  ownership, sensitive-buffer clearing, large-buffer bypass, and pool telemetry
- [TinyUa.Core/Binary/BinaryEncoderPool.cs](TinyUa.Core/Binary/BinaryEncoderPool.cs) — Bounded encoder cache
- [TinyUa.Transport/MessageChunk.cs](TinyUa.Transport/MessageChunk.cs) — OPC UA Part 6 chunking,
  segmented signing, encryption, and pooled wire buffers
- [TinyUa.Transport/SecureConnection.cs](TinyUa.Transport/SecureConnection.cs) — Secure-channel token
  rotation and message framing
- [TinyUa.Core/Security/SecurityPolicyFactory.cs](TinyUa.Core/Security/SecurityPolicyFactory.cs) —
  Security policy normalization and construction
- [TinyUa.Core/Types/Variant.cs](TinyUa.Core/Types/Variant.cs) — Variant inference and explicit conversion
- [TinyUa.Core/Types/UaTypes.cs](TinyUa.Core/Types/UaTypes.cs) — `StatusCode`, `DataValue`,
  `QualifiedName`, and `LocalizedText`
- [TinyUa.Benchmarks/MemoryKepwareBenchmark.cs](TinyUa.Benchmarks/MemoryKepwareBenchmark.cs) —
  Continuous batch Read/Write memory and pool monitor
- [TinyUa.Example/Program.cs](TinyUa.Example/Program.cs) — Runnable examples and self-test

## Engineering Conventions

- **Public client namespaces**: use `TinyUa.Client`, `TinyUa.Client.Services`,
  `TinyUa.Client.Subscriptions`, and `TinyUa.Client.Discovery`. Do not use the removed
  `TinyUa.Core.Client*` namespaces.
- **InternalsVisibleTo**: Core exposes internals to Transport, Client, Security.Tests, and
  Benchmarks; Transport exposes internals to Client and Security.Tests; Client exposes internals
  to Client.Tests, Security.Tests, and Benchmarks. Explorer uses public APIs only.
- **Nullability**: enabled project-wide. Public service calls may return null in
  `ErrorMode.ReturnNull`; documentation and callers must handle it.
- **Options snapshot**: `UaClient` deep-clones `UaClientOptions`. Mutating the caller's options
  after construction must not affect a running client.
- **Read/Write results**: single Read returns `ReadResult?`, batch returns `ReadResult[]?`; single
  Write returns `WriteResult?`, batch returns `WriteResult[]?`. Both result classes carry
  non-nullable `NodeId` and `StatusCode`; `ReadResult.DataValue` is nullable.
- **StatusCode**: use `result.StatusCode.IsGood`, not
  `result.DataValue?.StatusCode?.IsGood`. Use `GetStatusText()` for diagnostics.
- **Variant inference**: omit the explicit type to let the `Variant` constructor infer it from the
  CLR value. An explicit `VariantType` converts scalar values through the constructor's internal
  conversion path (for example `double` to `float`) rather than relying on a direct cast.
- **DataChangeHandler**: `(NodeId nodeId, object? value, StatusCode status)`.
  `DataChangeHandlerEx` additionally receives nullable source/server timestamps.
- **Subscription dispatch**: one bounded, ordered callback queue per subscription. `Wait` is the
  lossless default and propagates backpressure to the finite Publish window. Drop policies update
  `DroppedNotificationMessages`; `PendingNotificationMessages` reports queued Publish responses.
- **Publish credits**: `MaxPublishRequests` is session-level, not per monitored item. All
  subscriptions share one `PublishEngine`.
- **Reconnect ownership**: only `UaClient` changes `ClientState`. Every socket/request failure
  enters through `EnterReconnecting`; `ReconnectEngine` performs single-flight recovery but does
  not set client state. `StateChanged` must fire only for actual changes.
- **Reconnect recovery**: stop live publishing, reconnect transport, reactivate or recreate the
  session, Republish through the same bounded dispatch path when possible, otherwise rebuild
  monitored items, then restart publishing.
- **Buffer ownership**: protocol buffers use class-based `BufferLease`; every rent must have one
  owner and one dispose. Sensitive used bytes are zeroed before return. Buffers over 1 MiB bypass
  ArrayPool to avoid retaining transient huge messages.
- **Encoder pooling**: return encoders through `BinaryEncoderPool`; encoders above its retention
  cap are discarded. Do not keep borrowed encoder segments after return.
- **Receive path**: `UaSocketClient` owns one pooled receive ring, drains all complete frames before
  reading again, grows for partial large frames, and shrinks after oversized traffic.
- **Send path**: None-security MSG may use a fixed header plus gather send; secure/chunked messages
  stream pooled chunks. Request callbacks must be registered before sending.
- **Security policy names**: prefer compact short names: `None`, `Basic256Sha256`,
  `Aes128Sha256RsaOaep`, `Aes256Sha256RsaPss`.
- **Certificate discovery**: secure clients normally discover the server certificate via
  GetEndpoints (`AutoDiscoverServerCertificate`). `AutoAcceptServerCertificate=false` performs
  built-in date/EKU/chain-integrity checks, but unknown roots are allowed and CRLs are not checked.
- **OPN vs MSG**: secure OpenSecureChannel messages use SignAndEncrypt. Regular MSG uses the
  configured `MessageSecurityMode`; None policy remains unsecured.
- **Token rotation**: `SecureConnection` tracks current/next/previous
  `ChannelSecurityToken`; `SetChannel()` drives Issue/Renew transitions.
- **No directives**: do not add `#region`, `#if`, or `#pragma`.
- **Fluent builder**: `UaClient.ConnectTo(url).WithSecurity(...).BuildAndRunAsync()`.

## Namespace Map

| Namespace | Project |
|-----------|---------|
| `TinyUa.Core` | Core interfaces and base protocol types |
| `TinyUa.Core.Binary` | BinaryEncoder, BinaryDecoder, codecs, pools |
| `TinyUa.Core.Types` | NodeId, Variant, StatusCode, DataValue |
| `TinyUa.Core.Logging` | ILogger, NullLogger, DelegateLogger, FileLogger |
| `TinyUa.Core.Security` | Public security enums/options support and internal policy factory |
| `TinyUa.Core.Security.Certificates` | Certificate generation/loading/validation |
| `TinyUa.Core.Security.Cryptography` | AES, RSA, PSHA-256 |
| `TinyUa.Core.Security.Policies` | Concrete security policies |
| `TinyUa.Transport` | MessageChunk, SecureConnection |
| `TinyUa.Client` | UaClient, ClientBuilder, UaClientOptions, lifecycle/errors |
| `TinyUa.Client.Connection` | ConnectionOrchestrator, UaConnection, UaSocketClient, reconnect/keep-alive |
| `TinyUa.Client.Discovery` | EndpointDiscoverer, DiscoveredEndpoint |
| `TinyUa.Client.Security` | Client certificate and user-identity construction |
| `TinyUa.Client.Services` | Read/Write/Browse/Session/Subscription service models |
| `TinyUa.Client.Subscriptions` | PublishEngine, Subscription, routing, dispatch/backpressure |

## Testing

- **Client.Tests** covers concurrency, state transitions, backpressure, robustness, and regression tests.
- **Security.Tests** starts an in-process OPCF server for security integration tests.
- **selftest** runs an in-process OPCF server at `opc.tcp://localhost:48440`.
- **none** validates live connection, Browse, batch Read/Write, DemoCH/Data writes, and Wait backpressure.
- **substress** exercises fast and deliberately slow subscription callbacks.
- **memory** continuously batch-reads/writes DemoCH/Data and reports allocation/GC/pool usage.
- Live benchmark commands accept an optional endpoint URL after the subcommand and otherwise use
  `opc.tcp://localhost:49320`.
