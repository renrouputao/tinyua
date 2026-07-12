using TinyUa.Client.Connection;

namespace TinyUa.Client.Tests;

public class KeepAliveManagerTests
{
    [Theory]
    // Negative configured value disables the session keep-alive heartbeat.
    [InlineData(3600000, -1, 0)]
    [InlineData(3600000, -500, 0)]
    // Positive configured value is used as given, floored to 250 ms.
    [InlineData(3600000, 5000, 5000)]
    [InlineData(3600000, 100, 250)]
    // 0 = automatic: sessionTimeout / 4 clamped to [1000, 60000].
    [InlineData(3600000, 0, 60000)]   // 1 h / 4 = 15 min -> capped at 60 s
    [InlineData(8000, 0, 2000)]       // 8 s / 4 = 2 s
    [InlineData(2000, 0, 1000)]       // 2 s / 4 = 500 ms -> floored to 1 s
    // Unknown/invalid session timeout falls back to a 60 s threshold.
    [InlineData(0, 0, 60000)]
    [InlineData(-1, 0, 60000)]
    public void ComputeSessionIdleThreshold_ResolvesExpectedThreshold(
        int sessionTimeoutMs, int configuredMs, int expected)
    {
        Assert.Equal(expected,
            KeepAliveManager.ComputeSessionIdleThreshold(sessionTimeoutMs, configuredMs));
    }
}
