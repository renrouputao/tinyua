using System;

namespace TinyUa.Core.Logging
{
    /// <summary>
    /// An <see cref="ILogger"/> implementation that delegates log output to a user-supplied callback action.
    /// </summary>
    public sealed class DelegateLogger : ILogger
    {
        private readonly Action<LogLevel, Exception?, string> _sink;
        private readonly LogLevel _minLevel;

        /// <summary>
        /// Initializes a new instance of the <see cref="DelegateLogger"/> class.
        /// </summary>
        /// <param name="sink">The callback action that receives each log entry.</param>
        /// <param name="minLevel">The minimum <see cref="LogLevel"/> to log. Defaults to <see cref="LogLevel.Debug"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sink"/> is <c>null</c>.</exception>
        public DelegateLogger(Action<LogLevel, Exception?, string> sink, LogLevel minLevel = LogLevel.Debug)
        {
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _minLevel = minLevel;
        }

        /// <inheritdoc />
        public void Log(LogLevel level, Exception? exception, string message)
        {
            if (level < _minLevel) return;
            _sink(level, exception, message);
        }

        /// <inheritdoc />
        public bool IsEnabled(LogLevel level) => level >= _minLevel;
    }
}
