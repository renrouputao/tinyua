using System.Collections.Concurrent;
using System.Threading;

namespace TinyUa.Core.Binary
{
    /// <summary>Observable state of the bounded BinaryEncoder cache.</summary>
    internal readonly record struct BinaryEncoderPoolStatistics(
        int RetainedEncoders,
        long RetainedCapacityBytes,
        long Rents,
        long Reuses,
        long Created,
        long Returns,
        long Discarded);

    /// <summary>
    /// Bounded, thread-safe pool of reusable <see cref="BinaryEncoder"/> instances shared by the
    /// send/encode paths in TinyUa.Client and TinyUa.Transport.
    /// </summary>
    internal static class BinaryEncoderPool
    {
        private static readonly ConcurrentBag<BinaryEncoder> s_pool = new();
        private static int s_count;
        private static long s_retainedCapacityBytes;
        private static long s_rents;
        private static long s_reuses;
        private static long s_created;
        private static long s_returns;
        private static long s_discarded;

        // Encoders whose buffer grew beyond this after a one-off large message are dropped instead
        // of pooled, so a single huge message doesn't pin a large buffer for the process lifetime.
        private const int MaxPooledEncoderCapacity = 512 * 1024;

        // Upper bound on pooled instances so a concurrency spike doesn't leave an unbounded number
        // of encoders (up to 512 KiB each) parked for the process lifetime.
        private const int MaxPoolSize = 32;

        internal static BinaryEncoder Rent()
        {
            Interlocked.Increment(ref s_rents);
            if (s_pool.TryTake(out var e))
            {
                Interlocked.Decrement(ref s_count);
                Interlocked.Add(ref s_retainedCapacityBytes, -e.Capacity);
                Interlocked.Increment(ref s_reuses);
                e.Reset();
                return e;
            }
            Interlocked.Increment(ref s_created);
            return new BinaryEncoder(4096);
        }

        internal static void Return(BinaryEncoder encoder)
        {
            Interlocked.Increment(ref s_returns);
            if (encoder.Capacity > MaxPooledEncoderCapacity)
            {
                Interlocked.Increment(ref s_discarded);
                return;
            }
            if (Interlocked.Increment(ref s_count) > MaxPoolSize)
            {
                Interlocked.Decrement(ref s_count);
                Interlocked.Increment(ref s_discarded);
                return;
            }
            Interlocked.Add(ref s_retainedCapacityBytes, encoder.Capacity);
            s_pool.Add(encoder);
        }

        internal static BinaryEncoderPoolStatistics GetStatistics() => new(
            Volatile.Read(ref s_count),
            Interlocked.Read(ref s_retainedCapacityBytes),
            Interlocked.Read(ref s_rents),
            Interlocked.Read(ref s_reuses),
            Interlocked.Read(ref s_created),
            Interlocked.Read(ref s_returns),
            Interlocked.Read(ref s_discarded));
    }
}
