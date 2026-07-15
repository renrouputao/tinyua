using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;

namespace TinyUa.Core.Binary
{
    /// <summary>Classifies protocol buffers for clearing before they are returned to a shared pool.</summary>
    internal enum BufferSensitivity
    {
        Normal,
        Sensitive
    }

    /// <summary>Observable counters for TinyUa's ArrayPool rentals. Values do not include ArrayPool's private cache.</summary>
    internal readonly record struct BufferPoolStatistics(
        long Rents,
        long Returns,
        long DirectAllocations,
        long ActivePooledBuffers,
        long ActivePooledBytes,
        long PeakActivePooledBuffers,
        long PeakActivePooledBytes);

    /// <summary>
    /// Owns one protocol buffer rented from the internal pool. A lease is deliberately a class:
    /// copying a value-type owner is a common source of double returns in asynchronous I/O code.
    /// </summary>
    internal sealed class BufferLease : IDisposable
    {
        private static long s_rents;
        private static long s_returns;
        private static long s_directAllocations;
        private static long s_activePooledBuffers;
        private static long s_activePooledBytes;
        private static long s_peakActivePooledBuffers;
        private static long s_peakActivePooledBytes;
        private byte[]? _buffer;
        private readonly bool _pooled;
        private readonly BufferSensitivity _sensitivity;
        private int _length;

        private BufferLease(byte[] buffer, bool pooled, BufferSensitivity sensitivity)
        {
            _buffer = buffer;
            _pooled = pooled;
            _sensitivity = sensitivity;
        }

        internal static BufferLease Rent(int minimumLength, BufferSensitivity sensitivity = BufferSensitivity.Normal)
        {
            if (minimumLength < 0) throw new ArgumentOutOfRangeException(nameof(minimumLength));

            // Pooling very large OPC UA messages makes a transient 16/64 MiB request resident
            // for the rest of the process. Such buffers are exact, non-pooled allocations.
            const int maxPooledLength = 1024 * 1024;
            if (minimumLength > maxPooledLength)
            {
                var direct = GC.AllocateUninitializedArray<byte>(minimumLength);
                TrackRent(direct.Length, pooled: false);
                return new BufferLease(direct, false, sensitivity);
            }

            return new BufferLease(RentSharedArray(minimumLength), true, sensitivity);
        }

        /// <summary>
        /// Rents an ArrayPool buffer for a long-lived transport ring. The caller must return it
        /// with <see cref="ReturnSharedArray"/> so diagnostics remain accurate.
        /// </summary>
        internal static byte[] RentSharedArray(int minimumLength)
        {
            if (minimumLength < 0) throw new ArgumentOutOfRangeException(nameof(minimumLength));
            var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, minimumLength));
            TrackRent(buffer.Length, pooled: true);
            return buffer;
        }

        /// <summary>Returns an externally-owned shared buffer rented by <see cref="RentSharedArray"/>.</summary>
        internal static void ReturnSharedArray(byte[] buffer, BufferSensitivity sensitivity = BufferSensitivity.Normal, int usedLength = 0)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (sensitivity == BufferSensitivity.Sensitive && usedLength > 0)
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, Math.Min(usedLength, buffer.Length)));

            TrackReturn(buffer.Length, pooled: true);
            ArrayPool<byte>.Shared.Return(buffer);
        }

        internal static BufferPoolStatistics GetStatistics() => new(
            Interlocked.Read(ref s_rents),
            Interlocked.Read(ref s_returns),
            Interlocked.Read(ref s_directAllocations),
            Interlocked.Read(ref s_activePooledBuffers),
            Interlocked.Read(ref s_activePooledBytes),
            Interlocked.Read(ref s_peakActivePooledBuffers),
            Interlocked.Read(ref s_peakActivePooledBytes));

        internal int Capacity => GetBuffer().Length;

        internal int Length
        {
            get => Volatile.Read(ref _length);
            set
            {
                if ((uint)value > (uint)Capacity) throw new ArgumentOutOfRangeException(nameof(value));
                Volatile.Write(ref _length, value);
            }
        }

        internal byte[] Array => GetBuffer();

        internal Span<byte> Span => GetBuffer().AsSpan(0, Length);

        internal Memory<byte> Memory => GetBuffer().AsMemory(0, Length);

        internal Span<byte> CapacitySpan => GetBuffer().AsSpan();

        internal ArraySegment<byte> Segment => new(GetBuffer(), 0, Length);

        public void Dispose()
        {
            var buffer = Interlocked.Exchange(ref _buffer, null);
            if (buffer == null) return;

            if (_sensitivity == BufferSensitivity.Sensitive)
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, Math.Min(Volatile.Read(ref _length), buffer.Length)));

            if (_pooled)
                ReturnSharedArray(buffer);
            else
                TrackReturn(buffer.Length, pooled: false);
        }

        private static void TrackRent(int length, bool pooled)
        {
            Interlocked.Increment(ref s_rents);
            if (!pooled)
            {
                Interlocked.Increment(ref s_directAllocations);
                return;
            }

            var activeBuffers = Interlocked.Increment(ref s_activePooledBuffers);
            var activeBytes = Interlocked.Add(ref s_activePooledBytes, length);
            UpdatePeak(ref s_peakActivePooledBuffers, activeBuffers);
            UpdatePeak(ref s_peakActivePooledBytes, activeBytes);
        }

        private static void TrackReturn(int length, bool pooled)
        {
            Interlocked.Increment(ref s_returns);
            if (!pooled) return;

            Interlocked.Decrement(ref s_activePooledBuffers);
            Interlocked.Add(ref s_activePooledBytes, -length);
        }

        private static void UpdatePeak(ref long target, long value)
        {
            var observed = Volatile.Read(ref target);
            while (value > observed)
            {
                var previous = Interlocked.CompareExchange(ref target, value, observed);
                if (previous == observed) return;
                observed = previous;
            }
        }

        private byte[] GetBuffer() => _buffer ?? throw new ObjectDisposedException(nameof(BufferLease));
    }
}
