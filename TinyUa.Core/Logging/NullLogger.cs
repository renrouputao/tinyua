using System;

namespace TinyUa.Core.Logging
{
    /// <summary>
    /// A no-op <see cref="ILogger"/> implementation that discards all log entries.
    /// Use <see cref="Instance"/> to obtain the singleton instance.
    /// </summary>
    public sealed class NullLogger : ILogger
    {
        /// <summary>
        /// The singleton instance of <see cref="NullLogger"/>.
        /// </summary>
        public static readonly NullLogger Instance = new();

        private NullLogger() { }

        /// <inheritdoc />
        public void Log(LogLevel level, Exception? exception, string message) { }

        /// <inheritdoc />
        public bool IsEnabled(LogLevel level) => false;
    }
}
