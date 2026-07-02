using Xunit;

namespace TinyUa.Security.Tests;

/// <summary>
/// xUnit collection that shares a single <see cref="OpcfSecureServerFixture"/> across all
/// tests in the security test assembly. The fixture starts the in-process OPCF server once
/// (exposing None + Basic256Sha256 + Aes128 + Aes256 policies on port 48420) and disposes
/// it when all tests in the collection complete.
///
/// Tests within a collection run sequentially by default, avoiding concurrent-connect
/// interference against the shared server.
/// </summary>
[CollectionDefinition("SecureServer")]
public sealed class SecureServerCollection : ICollectionFixture<OpcfSecureServerFixture> { }
