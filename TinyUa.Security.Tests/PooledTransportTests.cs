using System.Buffers.Binary;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using TinyUa.Transport;

namespace TinyUa.Security.Tests;

public class PooledTransportTests
{
    [Fact]
    public void UnsecuredChunk_LeaseOwnsWireBytesUntilDisposed()
    {
        var chunk = new MessageChunk(new NoneSecurityPolicy(), new byte[] { 0xA1, 0xB2 });
        chunk.MessageHeader.ChannelId = 17;
        ((SymmetricAlgorithmHeader)chunk.SecurityHeader).TokenId = 23;
        chunk.SequenceHeader.SequenceNumber = 31;
        chunk.SequenceHeader.RequestId = 37;

        var wire = chunk.ToBufferLease();
        try
        {
            Assert.Equal(26, wire.Length);
            Assert.Equal("MSG", System.Text.Encoding.ASCII.GetString(wire.Array, 0, 3));
            Assert.Equal((uint)26, BinaryPrimitives.ReadUInt32LittleEndian(wire.Array.AsSpan(4, 4)));
            Assert.Equal((uint)17, BinaryPrimitives.ReadUInt32LittleEndian(wire.Array.AsSpan(8, 4)));
            Assert.Equal((uint)23, BinaryPrimitives.ReadUInt32LittleEndian(wire.Array.AsSpan(12, 4)));
            Assert.Equal((uint)31, BinaryPrimitives.ReadUInt32LittleEndian(wire.Array.AsSpan(16, 4)));
            Assert.Equal((uint)37, BinaryPrimitives.ReadUInt32LittleEndian(wire.Array.AsSpan(20, 4)));
            Assert.Equal(new byte[] { 0xA1, 0xB2 }, wire.Array[24..26]);
        }
        finally
        {
            wire.Dispose();
            wire.Dispose();
        }
    }
}
