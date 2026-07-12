using System;

namespace TinyUa.Client
{
    /// <summary>
    /// Owns the client lifecycle state, its lock, and the StateChanged event so every transition
    /// follows the same discipline: decide-and-set under the lock, raise the event outside it.
    ///
    /// Legal transitions:
    /// <code>
    ///   Disconnected  -> Connecting
    ///   Connecting    -> Connected | Reconnecting | Disconnecting | Disconnected
    ///   Connected     -> Reconnecting | Disconnecting | Disconnected
    ///   Reconnecting  -> Connected | Connecting | Disconnecting | Disconnected
    ///   Disconnecting -> Disconnected
    /// </code>
    /// Callers express their guards in the decide callback; the machine guarantees atomicity of
    /// the decision and consistent event ordering.
    /// </summary>
    internal sealed class ClientStateMachine
    {
        private readonly object _lock = new();
        private volatile ClientState _state = ClientState.Disconnected;

        internal ClientState State => _state;

        /// <summary>Raised after each transition (and for replayed states), outside the lock.</summary>
        internal event Action<ClientState>? StateChanged;

        /// <summary>
        /// Runs <paramref name="decide"/> under the state lock. The callback receives the current
        /// state and returns the state to transition to, or null to leave the state unchanged.
        /// Callers may atomically update their own guarded fields inside the callback. When a
        /// transition happens, StateChanged fires outside the lock and the method returns true.
        /// </summary>
        internal bool Transition(Func<ClientState, ClientState?> decide)
        {
            ClientState? next;
            lock (_lock)
            {
                next = decide(_state);
                if (next.HasValue)
                    _state = next.Value;
            }
            if (next.HasValue)
                StateChanged?.Invoke(next.Value);
            return next.HasValue;
        }

        /// <summary>Unconditionally transitions to <paramref name="state"/> and raises StateChanged.</summary>
        internal void Set(ClientState state)
        {
            lock (_lock)
                _state = state;
            StateChanged?.Invoke(state);
        }

        /// <summary>
        /// Raises StateChanged for <paramref name="state"/> without changing the current state —
        /// used to replay the Disconnecting/Disconnected pair when StopAsync is called on an
        /// already-disconnected client.
        /// </summary>
        internal void Replay(ClientState state) => StateChanged?.Invoke(state);
    }
}
