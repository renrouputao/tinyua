using System;

namespace TinyUa.Core.Logging
{
    public static class LoggerExtensions
    {
        public static void LogTrace(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Trace))
                logger.Log(LogLevel.Trace, null, message);
        }

        public static void LogTrace(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Trace))
                logger.Log(LogLevel.Trace, ex, message);
        }

        public static void LogDebug(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Debug))
                logger.Log(LogLevel.Debug, null, message);
        }

        public static void LogDebug(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Debug))
                logger.Log(LogLevel.Debug, ex, message);
        }

        public static void LogInformation(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Information))
                logger.Log(LogLevel.Information, null, message);
        }

        public static void LogInformation(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Information))
                logger.Log(LogLevel.Information, ex, message);
        }

        public static void LogWarning(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Warning))
                logger.Log(LogLevel.Warning, null, message);
        }

        public static void LogWarning(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Warning))
                logger.Log(LogLevel.Warning, ex, message);
        }

        public static void LogError(this ILogger logger, string message)
        {
            if (logger.IsEnabled(LogLevel.Error))
                logger.Log(LogLevel.Error, null, message);
        }

        public static void LogError(this ILogger logger, Exception? ex, string message)
        {
            if (logger.IsEnabled(LogLevel.Error))
                logger.Log(LogLevel.Error, ex, message);
        }
    }
}
