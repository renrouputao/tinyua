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
