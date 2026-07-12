using System.Collections.Concurrent;
using System.Threading;

namespace TinyUa.Core.Binary
{
    /// <summary>
    /// Bounded, thread-safe pool of reusable <see cref="BinaryEncoder"/> instances shared by the
    /// send/encode paths in TinyUa.Client and TinyUa.Transport.
    /// </summary>
    internal static class BinaryEncoderPool
    {
        private static readonly ConcurrentBag<BinaryEncoder> s_pool = new();
        private static int s_count;

        // Encoders whose buffer grew beyond this after a one-off large message are dropped instead
        // of pooled, so a single huge message doesn't pin a large buffer for the process lifetime.
        private const int MaxPooledEncoderCapacity = 512 * 1024;

        // Upper bound on pooled instances so a concurrency spike doesn't leave an unbounded number
        // of encoders (up to 512 KiB each) parked for the process lifetime.
        private const int MaxPoolSize = 32;

        internal static BinaryEncoder Rent()
        {
            if (s_pool.TryTake(out var e))
            {
                Interlocked.Decrement(ref s_count);
                e.Reset();
                return e;
            }
            return new BinaryEncoder(4096);
        }

        internal static void Return(BinaryEncoder encoder)
        {
            if (encoder.Capacity > MaxPooledEncoderCapacity)
                return;
            if (Interlocked.Increment(ref s_count) > MaxPoolSize)
            {
                Interlocked.Decrement(ref s_count);
                return;
            }
            s_pool.Add(encoder);
        }
    }
}
