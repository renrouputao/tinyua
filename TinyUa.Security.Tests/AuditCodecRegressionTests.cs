using System.Text;
using TinyUa.Client.Connection;
using TinyUa.Client.Services;
using TinyUa.Core;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Security.Tests;

[Collection("SecureServer")]
public class AuditCodecRegressionTests
{
    [Fact]
    public void NullArrayPreservesItsTypeAndNullLength()
    {
        byte[] bytes = { 0x86, 255, 255, 255, 255 };
        var value = VariantCodec.Decode(new BinaryDecoder(bytes));
        Assert.True(value.IsArray);
        Assert.Null(value.Value);
        Assert.Equal(VariantType.Int32, value.VariantType);
        using var encoder = new BinaryEncoder();
        VariantCodec.Encode(encoder, value);
        Assert.Equal(bytes, encoder.ToByteArray());
    }

    [Fact]
    public void ByteArrayRemainsDistinctFromByteString()
    {
        byte[] bytes = { 7, 8, 255 };
        using var encoder = new BinaryEncoder();
        VariantCodec.Encode(encoder, new Variant(bytes, VariantType.Byte));
        var encoded = encoder.ToByteArray();
        Assert.Equal(0x83, encoded[0]);
        var decoded = VariantCodec.Decode(new BinaryDecoder(encoded));
        Assert.True(decoded.IsArray);
        Assert.Equal(bytes, Assert.IsType<byte[]>(decoded.Value));
        using var reference = new Opc.Ua.BinaryDecoder(encoded, Opc.Ua.ServiceMessageContext.GlobalContext);
        Assert.Equal(bytes, Assert.IsType<byte[]>(reference.ReadVariant(null).Value));
        Assert.False(new Variant(bytes).IsArray);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MatricesInteroperateWithOpcf(bool clrMatrix)
    {
        var value = clrMatrix ? new Variant(new int[,] { { 1, 2 }, { 3, 4 } })
            : new Variant(new[] { 1, 2, 3, 4 }) { Dimensions = new[] { 2, 2 } };
        using var encoder = new BinaryEncoder();
        VariantCodec.Encode(encoder, value);
        using var reference = new Opc.Ua.BinaryDecoder(encoder.ToByteArray(), Opc.Ua.ServiceMessageContext.GlobalContext);
        var matrix = Assert.IsType<Opc.Ua.Matrix>(reference.ReadVariant(null).Value);
        Assert.Equal(new[] { 2, 2 }, matrix.Dimensions);
        Assert.Equal(new[] { 1, 2, 3, 4 }, Assert.IsType<int[]>(matrix.Elements));

        using var referenceEncoder = new Opc.Ua.BinaryEncoder(Opc.Ua.ServiceMessageContext.GlobalContext);
        referenceEncoder.WriteVariant(null, new Opc.Ua.Variant(matrix));
        var decoded = VariantCodec.Decode(new BinaryDecoder(referenceEncoder.CloseAndReturnBuffer()));
        Assert.Equal(new[] { 2, 2 }, decoded.Dimensions);
        Assert.Equal(new[] { 1, 2, 3, 4 }, Assert.IsType<int[]>(decoded.Value));
    }

    public static IEnumerable<object[]> TimestampMasks => Enumerable.Range(0, 16).Select(i => new object[] { i });

    [Theory]
    [MemberData(nameof(TimestampMasks))]
    public void DataValueFieldsMatchStandardOrder(int mask)
    {
        var source = new DateTime(2026, 9, 24, 0, 0, 0, DateTimeKind.Utc);
        var expected = new DataValue(new Variant(42))
        {
            StatusCode = StatusCode.Good,
            SourceTimestamp = (mask & 1) != 0 ? source : null,
            ServerTimestamp = (mask & 2) != 0 ? source.AddSeconds(1) : null,
            SourcePicoseconds = (mask & 4) != 0 ? (ushort)123 : null,
            ServerPicoseconds = (mask & 8) != 0 ? (ushort)456 : null
        };
        using var encoder = new BinaryEncoder();
        expected.Encode(encoder);
        var bytes = encoder.ToByteArray();
        // Build the standard field order independently of DataValue.Encode.
        using var wire = new BinaryEncoder();
        wire.WriteByte(bytes[0]);
        VariantCodec.Encode(wire, new Variant(42));
        if ((mask & 1) != 0) wire.WriteDateTime(source);
        if ((mask & 4) != 0) wire.WriteUInt16(123);
        if ((mask & 2) != 0) wire.WriteDateTime(source.AddSeconds(1));
        if ((mask & 8) != 0) wire.WriteUInt16(456);
        Assert.Equal(wire.ToByteArray(), bytes);
        var actual = DataValue.Decode(new BinaryDecoder(wire.ToByteArray()));
        Assert.Equal(expected.SourceTimestamp, actual.SourceTimestamp);
        Assert.Equal(expected.ServerTimestamp, actual.ServerTimestamp);
        Assert.Equal(expected.SourcePicoseconds, actual.SourcePicoseconds);
        Assert.Equal(expected.ServerPicoseconds, actual.ServerPicoseconds);
        // OPCF normalizes picoseconds when the corresponding timestamp is absent.
        if (((mask & 4) == 0 || (mask & 1) != 0) && ((mask & 8) == 0 || (mask & 2) != 0))
        {
            using var reference = new Opc.Ua.BinaryDecoder(bytes, Opc.Ua.ServiceMessageContext.GlobalContext);
            var result = reference.ReadDataValue(null);
            if (expected.SourceTimestamp.HasValue) Assert.Equal(source, result.SourceTimestamp);
            if (expected.ServerTimestamp.HasValue) Assert.Equal(source.AddSeconds(1), result.ServerTimestamp);
            Assert.Equal(expected.SourcePicoseconds ?? 0, result.SourcePicoseconds);
            Assert.Equal(expected.ServerPicoseconds ?? 0, result.ServerPicoseconds);
        }
    }

    [Theory]
    [InlineData("ns=2;s=Line;Part", "Line;Part")]
    [InlineData("ns=2;s= Line;Part ", " Line;Part ")]
    [InlineData("ns=2;s=ns=3;i=12", "ns=3;i=12")]
    public void NodeIdPreservesEntireStringIdentifier(string text, string identifier)
    {
        var node = NodeId.Parse(text);
        Assert.Equal(identifier, node.Identifier);
        Assert.Equal(node, NodeId.Parse(node.ToString()));
        Assert.Equal(identifier, Opc.Ua.NodeId.Parse(text).Identifier);
    }

    [Fact]
    public void OpaqueNodeIdsUseContentEqualityAndExpandedMetadata()
    {
        var left = new NodeId(new byte[] { 1, 2 }, 2);
        var right = new NodeId(new byte[] { 1, 2 }, 2);
        Assert.Equal(left, right);
        Assert.Equal(left.GetHashCode(), right.GetHashCode());
        Assert.Equal(0, left.CompareTo(right));
        right.ServerIndex = 1;
        Assert.NotEqual(left, right);
        left.NamespaceUri = "urn:line;station";
        Assert.Equal(left, NodeId.Parse(left.ToString()));
        Assert.NotEqual(0, left.CompareTo(new NodeId("1", 2)));
    }

    [Fact]
    public void MalformedCountsAreRejectedBeforeLargeAllocation()
    {
        using var encoder = new BinaryEncoder();
        encoder.WriteUInt32(1);
        encoder.WriteInt32(100_000);
        var bytes = encoder.ToByteArray();
        Assert.Throws<InvalidOperationException>(() => PublishResult.Decode(new BinaryDecoder(bytes)));
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidOperationException>(() => PublishResult.Decode(new BinaryDecoder(bytes)));
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 32_000);
        Assert.Throws<InvalidOperationException>(() => new BinaryDecoder(BitConverter.GetBytes(-2)).ReadByteString());
        Assert.Throws<InvalidOperationException>(() => new BinaryDecoder(new byte[1]).Skip(int.MaxValue));
    }

    [Fact]
    public void EndpointSelectionNeverDowngradesOrAcceptsForeignPolicyUri()
    {
        var endpoint = new EndpointDescription { SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", SecurityMode = MessageSecurityMode.Sign };
        Assert.Null(ConnectionOrchestrator.SelectEndpoint(new[] { endpoint }, "Basic256Sha256", MessageSecurityMode.SignAndEncrypt));
        endpoint.SecurityMode = MessageSecurityMode.SignAndEncrypt;
        Assert.Same(endpoint, ConnectionOrchestrator.SelectEndpoint(new[] { endpoint }, "Basic256Sha256", MessageSecurityMode.SignAndEncrypt));
        endpoint.SecurityPolicyUri = "https://untrusted.example/#Basic256Sha256";
        Assert.Null(ConnectionOrchestrator.SelectEndpoint(new[] { endpoint }, "Basic256Sha256", MessageSecurityMode.SignAndEncrypt));
    }

    [Fact]
    public async Task EncodeFailureReturnsPoolLeaseAndCredentialsNeverEnterLogs()
    {
        var messages = new List<string>();
        using var socket = new UaSocketClient(logger: new DelegateLogger((_, _, msg) => messages.Add(msg), LogLevel.Debug));
        var before = BinaryEncoderPool.GetStatistics();
        await Assert.ThrowsAsync<InvalidOperationException>(() => socket.SendRequestAsync(new ThrowingRequest()));
        await Assert.ThrowsAsync<InvalidOperationException>(() => socket.SendRequestNoWait(new ThrowingRequest()));
        var after = BinaryEncoderPool.GetStatistics();
        Assert.Equal(after.Rents - before.Rents, after.Returns - before.Returns);
        const string secret = "audit-dummy-password";
        await Assert.ThrowsAsync<InvalidOperationException>(() => socket.SendRequestAsync(new ActivateSessionRequest
        {
            Parameters = new ActivateSessionParameters { UserIdentity = UserIdentityToken.CreateUserName("audit", secret, "none") }
        }));
        var hex = BitConverter.ToString(Encoding.UTF8.GetBytes(secret)).Replace("-", " ");
        Assert.DoesNotContain(messages, m => m.Contains(secret) || m.Contains(hex));
    }

    private sealed class ThrowingRequest : IEncodable
    {
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString("sensitive test payload");
            throw new InvalidOperationException("Expected encoder failure");
        }
    }
}
