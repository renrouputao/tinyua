# Contributing to TinyUa

Thank you for your interest in contributing! This document outlines the process for contributing to the TinyUa project.

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Any IDE or editor (Visual Studio 2022, VS Code, JetBrains Rider)

### Build

```bash
dotnet build TinyUa.sln
```

### Run Tests

```bash
dotnet test
```

The test suite includes:
- **TinyUa.Client.Tests** — Client concurrency and robustness tests
- **TinyUa.Security.Tests** — Security integration tests (starts an in-process OPCF reference server)

### Run the Example

```bash
# Self-test against an in-process OPC UA server
dotnet run --project TinyUa.Example -- selftest

# Run all benchmarks
dotnet run --project TinyUa.Benchmarks
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch** for your change (`git checkout -b feature/my-feature`)
3. **Make your changes** — follow the existing code style in the file you're editing
4. **Build** — ensure `dotnet build TinyUa.sln` succeeds with zero errors
5. **Test** — ensure `dotnet test` passes
6. **Commit** with a descriptive message
7. **Push** and open a Pull Request

## Code Style

- Follow the existing conventions in the codebase
- Use C# nullable reference types (enabled project-wide)
- Public APIs should have clear, descriptive names
- Use the Fluent Builder pattern for configuration surfaces

## Pull Request Process

- PRs should target the `main` branch
- Keep changes focused — one feature or fix per PR
- Update or add tests when changing functionality
- Ensure all tests pass before requesting review

## Architecture Overview

```
TinyUa.Core ──────────── Binary encoding, types, security, logging
  └─ TinyUa.Transport ─ Message chunking, secure channel
       └─ TinyUa.Client ─ Fluent API, services, subscriptions, reconnect
            ├─ TinyUa.Example ── Console self-test app
            ├─ TinyUa.Explorer ─ WPF browser app
            ├─ TinyUa.Benchmarks ─ Performance benchmarks
            ├─ TinyUa.Client.Tests ─ Client tests
            └─ TinyUa.Security.Tests ─ Security integration tests
```

The core libraries (`TinyUa.Core`, `TinyUa.Transport`, `TinyUa.Client`) and benchmarks have **zero dependency** on the OPC Foundation SDK. The OPCF SDK is only used in test and example projects for reference comparisons.

## Questions?

Open an issue or start a discussion — we're happy to help.
