using System;

namespace TinyUa.Core.Logging
{
    /// <summary>
    /// Represents a logger that can write log entries and check whether a given log level is enabled.
    /// </summary>
    public interface ILogger
    {
        /// <summary>
        /// Writes a log entry with the specified level, optional exception, and message.
        /// </summary>
        /// <param name="level">The severity level of the log entry.</param>
        /// <param name="exception">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        void Log(LogLevel level, Exception? exception, string message);

        /// <summary>
        /// Returns a value indicating whether logging is enabled for the specified level.
        /// </summary>
        /// <param name="level">The log level to check.</param>
        /// <returns><c>true</c> if the specified log level is enabled; otherwise, <c>false</c>.</returns>
        bool IsEnabled(LogLevel level);
    }
}
