using System;

namespace TinyUa.Core.Logging
{
    /// <summary>
    /// Provides convenience extension methods for the <see cref="ILogger"/> interface that log at specific levels.
    /// </summary>
    public static class LoggerExtensions
    {
        /// <summary>
        /// Writes a trace-level log entry.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="message">The log message.</param>
        public static void LogTrace(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Trace))
                logger.Log(LogLevel.Trace, null, message);
        }

        /// <summary>
        /// Writes a trace-level log entry with an associated exception.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="ex">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        public static void LogTrace(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Trace))
                logger.Log(LogLevel.Trace, ex, message);
        }

        /// <summary>
        /// Writes a debug-level log entry.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="message">The log message.</param>
        public static void LogDebug(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Debug))
                logger.Log(LogLevel.Debug, null, message);
        }

        /// <summary>
        /// Writes a debug-level log entry with an associated exception.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="ex">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        public static void LogDebug(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Debug))
                logger.Log(LogLevel.Debug, ex, message);
        }

        /// <summary>
        /// Writes an information-level log entry.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="message">The log message.</param>
        public static void LogInformation(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Information))
                logger.Log(LogLevel.Information, null, message);
        }

        /// <summary>
        /// Writes an information-level log entry with an associated exception.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="ex">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        public static void LogInformation(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Information))
                logger.Log(LogLevel.Information, ex, message);
        }

        /// <summary>
        /// Writes a warning-level log entry.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="message">The log message.</param>
        public static void LogWarning(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Warning))
                logger.Log(LogLevel.Warning, null, message);
        }

        /// <summary>
        /// Writes a warning-level log entry with an associated exception.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="ex">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        public static void LogWarning(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Warning))
                logger.Log(LogLevel.Warning, ex, message);
        }

        /// <summary>
        /// Writes an error-level log entry.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="message">The log message.</param>
        public static void LogError(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Error))
                logger.Log(LogLevel.Error, null, message);
        }

        /// <summary>
        /// Writes an error-level log entry with an associated exception.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="ex">An optional exception associated with the log entry.</param>
        /// <param name="message">The log message.</param>
        public static void LogError(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Error))
                logger.Log(LogLevel.Error, ex, message);
        }
    }
}
