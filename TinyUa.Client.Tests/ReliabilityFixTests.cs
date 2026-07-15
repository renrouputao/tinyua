using TinyUa.Client.Connection;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

public class ReliabilityFixTests
{
    [Theory]
    [InlineData("opc.tcp://localhost", 4840)]
    [InlineData("opc.tcp://localhost:49320", 49320)]
    public void ReconnectEndpoint_UsesOpcUaDefaultPortWhenOmitted(string endpoint, int expectedPort)
    {
        Assert.Equal(expectedPort, ReconnectEngine.ResolvePort(new Uri(endpoint)));
    }

    [Theory]
    [InlineData(3600000, 2700000)]
    [InlineData(1000, 1000)]
    [InlineData(0, 2700000)]
    public void ChannelRenewInterval_UsesEffectiveLifetime(int lifetime, int expectedInterval)
    {
        Assert.Equal(expectedInterval, KeepAliveManager.ComputeChannelRenewInterval(lifetime));
    }

    [Fact]
    public void ExpandedNodeId_Variant_RoundTripsAsExpandedNodeId()
    {
        var original = new ExpandedNodeId("Demo.Node", 2);
        var encoder = new BinaryEncoder();
        VariantCodec.Encode(encoder, new Variant(original));

        var decoded = VariantCodec.Decode(new BinaryDecoder(encoder.ToByteArray()));

        Assert.Equal(VariantType.ExpandedNodeId, decoded.VariantType);
        Assert.IsType<ExpandedNodeId>(decoded.Value);
    }

    [Fact]
    public void AsyncFileLogger_Dispose_FlushesEntriesAlreadyAccepted()
    {
        var directory = Path.Combine(Path.GetTempPath(), "tinyua_logger_" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var logger = new FileLogger(directory, LogLevel.Debug, async: true))
            {
                for (var i = 0; i < 100; i++)
                    logger.Log(LogLevel.Information, null, $"flush-marker-{i}");
            }

            var path = Directory.GetFiles(directory, "TinyUa_*.log").Single();
            var lines = File.ReadAllLines(path);
            Assert.Equal(100, lines.Count(line => line.Contains("flush-marker-", StringComparison.Ordinal)));
        }
        finally
        {
            try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task UaClient_PublicStateHandler_Exception_DoesNotBreakLifecycle()
    {
        await using var client = new UaClient("opc.tcp://localhost:4840");
        var delivered = 0;
        client.StateChanged += _ => throw new InvalidOperationException("user callback failure");
        client.StateChanged += _ => Interlocked.Increment(ref delivered);

        var field = typeof(UaClient).GetField("_stateMachine",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        var stateMachine = Assert.IsType<ClientStateMachine>(field?.GetValue(client));

        stateMachine.Set(ClientState.Connected);

        Assert.Equal(1, delivered);
    }

    [Fact]
    public void ClientStateMachine_SetSameState_RaisesOnlyOnce()
    {
        var stateMachine = new ClientStateMachine();
        var delivered = 0;
        stateMachine.StateChanged += _ => delivered++;

        Assert.True(stateMachine.Set(ClientState.Reconnecting));
        Assert.False(stateMachine.Set(ClientState.Reconnecting));

        Assert.Equal(ClientState.Reconnecting, stateMachine.State);
        Assert.Equal(1, delivered);
    }
}
