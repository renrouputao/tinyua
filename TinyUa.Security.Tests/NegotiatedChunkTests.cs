using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TinyUa.Client.Connection;
using TinyUa.Client.Services;
using TinyUa.Core.Binary;
using TinyUa.Core.Security;
using TinyUa.Core.Types;
using TinyUa.Transport;

namespace TinyUa.Security.Tests;

public class NegotiatedChunkTests
{
    [Fact]
    public void NegotiatedMessageAndChunkLimitsAreEnforcedBeforeEncoding()
    {
        var connection = new SecureConnection(new NoneSecurityPolicy());
        connection.ApplyAcknowledge(new Acknowledge { ReceiveBufferSize = 8192, MaxMessageSize = 100, MaxChunkCount = 1 });
        Assert.Throws<UaException>(() => connection.MessageToBinary(new ArraySegment<byte>(new byte[101])));
        connection.ApplyAcknowledge(new Acknowledge { ReceiveBufferSize = 8192, MaxMessageSize = 0, MaxChunkCount = 1 });
        Assert.Throws<UaException>(() => connection.MessageToBinary(new ArraySegment<byte>(new byte[9000])));
        connection.ApplyAcknowledge(new Acknowledge { ReceiveBufferSize = 8192, MaxMessageSize = 0, MaxChunkCount = 0 });
        Assert.True(connection.MessageToBinary(new ArraySegment<byte>(new byte[9000])).Length > 9000);
    }

    [Fact]
    public void ConfiguredReceiveMessageLimitRejectsOversizedBody()
    {
        var sender = new SecureConnection(new NoneSecurityPolicy());
        var receiver = new SecureConnection(new NoneSecurityPolicy());
        receiver.SetReceiveLimits(100, 1);
        var wire = sender.MessageToBinary(new ArraySegment<byte>(new byte[101]));
        var decoder = new BinaryDecoder(wire);
        var header = Header.Decode(decoder);
        header.ChannelId = decoder.ReadUInt32();
        Assert.Throws<UaException>(() => receiver.ReceiveFromHeaderAndBody(header, decoder.GetRemainingBytes()));
    }

    [Theory]
    [InlineData(2147483647u)]
    [InlineData(27u)]
    [InlineData(29u)]
    public async Task InvalidAckLengthIsRejectedWithoutReadingOrAllocatingItsBody(uint length)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(3000);
        using var client = new UaSocketClient(2000);
        var accept = listener.AcceptTcpClientAsync(deadline.Token);
        await client.ConnectAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, deadline.Token);
        using var peer = await accept;
        var stream = peer.GetStream();
        var hello = client.SendHelloAsync("opc.tcp://localhost", cancellationToken: deadline.Token);
        await ReadFrameAsync(stream, deadline.Token);
        var header = new byte[8];
        "ACKF"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), length);
        await stream.WriteAsync(header, deadline.Token);
        await Assert.ThrowsAsync<UaException>(() => hello.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task Hello_SmallerServerReceiveBuffer_ChunksSubsequentRequests()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(5000);
        using var client = new UaSocketClient(3000);
        var accept = listener.AcceptTcpClientAsync(deadline.Token);
        await client.ConnectAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, deadline.Token);
        using var peer = await accept;
        var stream = peer.GetStream();
        var helloTask = client.SendHelloAsync("opc.tcp://localhost", cancellationToken: deadline.Token);
        await ReadFrameAsync(stream, deadline.Token);
        var encoder = new BinaryEncoder();
        new Acknowledge { ReceiveBufferSize = 8192, SendBufferSize = 65536 }.Encode(encoder);
        var ack = new byte[28];
        "ACKF"u8.CopyTo(ack);
        BinaryPrimitives.WriteInt32LittleEndian(ack.AsSpan(4), ack.Length);
        encoder.ToByteArray().CopyTo(ack, 8);
        await stream.WriteAsync(ack, deadline.Token);
        await helloTask;

        // Encode enough data to exceed the server's buffer but fit the old 64 KiB default.
        var request = new GetEndpointsRequest { EndpointUrl = new string('x', 20000) };
        await client.SendRequestNoWait(request);
        var bytes = new List<byte>();
        var chunks = 0;
        while (true)
        {
            var frame = await ReadFrameAsync(stream, deadline.Token);
            Assert.InRange(frame.Length, 24, 8192);
            bytes.AddRange(frame[24..]);
            chunks++;
            if (frame[3] == (byte)'F') break;
            Assert.Equal((byte)'C', frame[3]);
        }
        Assert.True(chunks > 1);
        var expected = new BinaryEncoder();
        request.Encode(expected);
        Assert.Equal(expected.ToByteArray(), bytes.ToArray());
    }

    [Fact]
    public void Ack_UsesPeerReceiveLimitRatherThanPeerSendLimit()
    {
        var connection = new SecureConnection(new NoneSecurityPolicy());
        var encoder = new BinaryEncoder();
        new Acknowledge { ReceiveBufferSize = 8192, SendBufferSize = 65536 }.Encode(encoder);
        connection.ReceiveFromHeaderAndBody(new Header { MessageType = MessageType.Acknowledge }, encoder.ToByteArray());
        var wire = connection.MessageToBinary(new ArraySegment<byte>(new byte[20000]));
        var offset = 0;
        while (offset < wire.Length)
        {
            var length = BinaryPrimitives.ReadInt32LittleEndian(wire.AsSpan(offset + 4));
            Assert.InRange(length, 24, 8192);
            offset += length;
        }
        Assert.Equal(wire.Length, offset);
    }

    [Fact]
    public async Task NoWaitDispatchStartsInWireOrderWithoutBlockingOnCallbacks()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(5000);
        using var client = new UaSocketClient(3000);
        var accept = listener.AcceptTcpClientAsync(deadline.Token);
        await client.ConnectAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, deadline.Token);
        using var peer = await accept;
        var stream = peer.GetStream();
        var hello = client.SendHelloAsync("opc.tcp://localhost", cancellationToken: deadline.Token);
        await ReadFrameAsync(stream, deadline.Token);
        using var ackEncoder = new BinaryEncoder();
        new Acknowledge().Encode(ackEncoder);
        var ack = new byte[28];
        "ACKF"u8.CopyTo(ack);
        BinaryPrimitives.WriteInt32LittleEndian(ack.AsSpan(4), ack.Length);
        ackEncoder.ToByteArray().CopyTo(ack, 8);
        await stream.WriteAsync(ack, deadline.Token);
        await hello;

        var received = new System.Collections.Concurrent.ConcurrentQueue<int>();
        var complete = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SecureConnection(new NoneSecurityPolicy());
        using var responses = new MemoryStream();
        for (var index = 0; index < 32; index++)
        {
            await client.SendRequestNoWait(new GetEndpointsRequest(), body =>
            {
                received.Enqueue(BitConverter.ToInt32(body));
                if (received.Count == 32) complete.TrySetResult(true);
                return release.Task;
            });
            var request = await ReadFrameAsync(stream, deadline.Token);
            var requestId = BinaryPrimitives.ReadUInt32LittleEndian(request.AsSpan(20));
            responses.Write(server.MessageToBinary(new ArraySegment<byte>(BitConverter.GetBytes(index)), requestId: requestId));
        }
        try
        {
            await stream.WriteAsync(responses.ToArray(), deadline.Token);
            await complete.Task.WaitAsync(deadline.Token);
            Assert.Equal(Enumerable.Range(0, 32), received.ToArray());
        }
        finally { release.TrySetResult(true); }
        await client.DisconnectAsync();
    }

    private static async Task<byte[]> ReadFrameAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[8];
        await stream.ReadExactlyAsync(header, ct);
        var frame = new byte[BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4))];
        header.CopyTo(frame, 0);
        await stream.ReadExactlyAsync(frame.AsMemory(8), ct);
        return frame;
    }
}
