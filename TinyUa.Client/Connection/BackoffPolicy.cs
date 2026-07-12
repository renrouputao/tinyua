using System;

namespace TinyUa.Client.Connection
{
    /// <summary>
    /// Exponential backoff progression shared by the initial-connect retry loop and the
    /// reconnect engine: starts at the initial delay and doubles up to the cap.
    /// Not thread-safe; each retry loop owns its own instance.
    /// </summary>
    internal sealed class BackoffPolicy
    {
        private readonly int _initialDelayMs;
        private readonly int _maxDelayMs;
        private int _currentDelayMs;

        internal BackoffPolicy(int initialDelayMs, int maxDelayMs)
        {
            _initialDelayMs = Math.Max(0, initialDelayMs);
            _maxDelayMs = Math.Max(_initialDelayMs, maxDelayMs);
            _currentDelayMs = _initialDelayMs;
        }

        /// <summary>Returns the delay to wait before the next attempt, then advances the progression.</summary>
        internal int NextDelay()
        {
            var delay = _currentDelayMs;
            _currentDelayMs = (int)Math.Min((long)_currentDelayMs * 2, _maxDelayMs);
            return delay;
        }

        /// <summary>Resets the progression back to the initial delay (e.g. after a successful attempt).</summary>
        internal void Reset() => _currentDelayMs = _initialDelayMs;
    }
}
