using TinyUa.Core.Security;
using Xunit;

namespace TinyUa.Security.Tests;

/// <summary>
/// Verifies that both the compact policy names used in the README/AGENTS docs
/// ("Aes128Sha256RsaOaep") and the underscored OPC UA spec suffix
/// ("Aes128_Sha256_RsaOaep") normalize to the same canonical policy URI, so neither
/// spelling produces a "no matching endpoint" failure at connect time.
/// </summary>
public class PolicyNameNormalizationTests
{
    private const string Prefix = "http://opcfoundation.org/UA/SecurityPolicy#";

    [Theory]
    [InlineData("Aes128Sha256RsaOaep", Prefix + "Aes128_Sha256_RsaOaep")]
    [InlineData("Aes128_Sha256_RsaOaep", Prefix + "Aes128_Sha256_RsaOaep")]
    [InlineData("Aes256Sha256RsaPss", Prefix + "Aes256_Sha256_RsaPss")]
    [InlineData("Aes256_Sha256_RsaPss", Prefix + "Aes256_Sha256_RsaPss")]
    [InlineData("Basic256Sha256", Prefix + "Basic256Sha256")]
    [InlineData("None", Prefix + "None")]
    public void NormalizePolicyUri_MapsBothSpellings(string input, string expected)
    {
        Assert.Equal(expected, SecurityPolicyFactory.NormalizePolicyUri(input));
    }

    [Fact]
    public void NormalizePolicyUri_EmptyOrNull_IsNone()
    {
        Assert.Equal(Prefix + "None", SecurityPolicyFactory.NormalizePolicyUri(""));
    }

    [Fact]
    public void NormalizePolicyUri_FullUri_PassesThrough()
    {
        var uri = Prefix + "Aes256_Sha256_RsaPss";
        Assert.Equal(uri, SecurityPolicyFactory.NormalizePolicyUri(uri));
    }

    [Fact]
    public void IsSecurePolicy_CompactName_IsTrue()
    {
        Assert.True(SecurityPolicyFactory.IsSecurePolicy("Aes128Sha256RsaOaep"));
        Assert.False(SecurityPolicyFactory.IsSecurePolicy("None"));
    }
}
