using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace TinyUa.Testing;

// A loopback-only test proxy shared with the live benchmark. Faults affect only test clients.
internal sealed class UaFaultProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<TcpClient, byte> _clients = new();
    private readonly List<Task> _workers = new();
    private readonly Uri? _upstream;
    private readonly Task _acceptLoop;
    private int _accepted;
    private int _writeRequests;

    internal string Url { get; }
    internal int Accepted => Volatile.Read(ref _accepted);
    internal int UnsecuredWriteRequests => Volatile.Read(ref _writeRequests);
    internal TaskCompletionSource<bool> FaultReached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int StallResponse { get; set; }
    internal int ForwardPrefixBytes { get; set; }
    internal bool CloseAtFault { get; set; }

    internal UaFaultProxy(string? upstream = null, int stallResponse = 1, int forwardPrefixBytes = 0,
        bool closeAtFault = false)
    {
        _upstream = upstream == null ? null : new Uri(upstream);
        StallResponse = stallResponse;
        ForwardPrefixBytes = forwardPrefixBytes;
        CloseAtFault = closeAtFault;
        _listener.Start();
        Url = $"opc.tcp://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
        _acceptLoop = AcceptAsync();
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                client.NoDelay = true;
                _clients.TryAdd(client, 0);
                Interlocked.Increment(ref _accepted);
                _workers.Add(HandleAsync(client));
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var lifetime = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
        {
            TcpClient? upstream = null;
            Task? upload = null;
            try
            {
                var downstream = client.GetStream();
                if (_upstream == null)
                {
                    await ReadFrameAsync(downstream, lifetime.Token); // HEL
                    var ack = new byte[28];
                    "ACKF"u8.CopyTo(ack);
                    BinaryPrimitives.WriteInt32LittleEndian(ack.AsSpan(4), ack.Length);
                    BinaryPrimitives.WriteUInt32LittleEndian(ack.AsSpan(12), 65536);
                    BinaryPrimitives.WriteUInt32LittleEndian(ack.AsSpan(16), 65536);
                    if (StallResponse == 1)
                        await ApplyFaultAsync(downstream, ack, lifetime.Token);
                    else
                    {
                        await downstream.WriteAsync(ack, lifetime.Token);
                        await ReadFrameAsync(downstream, lifetime.Token); // OPN
                        await ApplyFaultAsync(downstream, Array.Empty<byte>(), lifetime.Token);
                    }
                    return;
                }

                upstream = new TcpClient { NoDelay = true };
                await upstream.ConnectAsync(_upstream.Host, _upstream.Port > 0 ? _upstream.Port : 4840, lifetime.Token);
                var source = upstream.GetStream();
                upload = ForwardRequestsAsync(downstream, source, lifetime.Token);
                var download = ForwardResponsesAsync(source, downstream, lifetime.Token);
                await Task.WhenAny(upload, download);
                lifetime.Cancel();
                upstream.Dispose();
                client.Dispose();
                await Task.WhenAll(upload, download);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
            finally
            {
                lifetime.Cancel();
                upstream?.Dispose();
                client.Dispose();
                if (upload != null)
                {
                    try { await upload; } catch { }
                }
                _clients.TryRemove(client, out _);
            }
        }
    }

    private async Task ForwardResponsesAsync(NetworkStream source, NetworkStream destination, CancellationToken ct)
    {
        var count = 0;
        while (!ct.IsCancellationRequested)
        {
            var frame = await ReadFrameAsync(source, ct);
            if (++count == StallResponse)
            {
                await ApplyFaultAsync(destination, frame, ct);
                return;
            }
            await destination.WriteAsync(frame, ct);
        }
    }

    private async Task ForwardRequestsAsync(NetworkStream source, NetworkStream destination, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var frame = await ReadFrameAsync(source, ct);
            // None-security, single-chunk WriteRequest: ns=0;i=673 follows the fixed header.
            if (frame.Length >= 28 && frame.AsSpan(0, 4).SequenceEqual("MSGF"u8)
                && frame[24] == 1 && frame[25] == 0
                && BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(26)) == 673)
                Interlocked.Increment(ref _writeRequests);
            await destination.WriteAsync(frame, ct);
        }
    }

    private async Task ApplyFaultAsync(NetworkStream destination, byte[] frame, CancellationToken ct)
    {
        if (ForwardPrefixBytes > 0)
            await destination.WriteAsync(frame.AsMemory(0, Math.Min(ForwardPrefixBytes, frame.Length)), ct);
        FaultReached.TrySetResult(true);
        if (!CloseAtFault)
            await Task.Delay(Timeout.Infinite, ct);
    }

    private static async Task<byte[]> ReadFrameAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[8];
        await stream.ReadExactlyAsync(header, ct);
        var size = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4));
        if (size < 8 || size > 16 * 1024 * 1024)
            throw new IOException($"Invalid test frame length: {size}");
        var frame = new byte[size];
        header.CopyTo(frame, 0);
        await stream.ReadExactlyAsync(frame.AsMemory(8), ct);
        return frame;
    }

    internal void DropConnections()
    {
        foreach (var client in _clients.Keys)
            client.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        DropConnections();
        await _acceptLoop;
        await Task.WhenAll(_workers);
        _stop.Dispose();
    }
}
