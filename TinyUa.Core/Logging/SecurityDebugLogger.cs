using System;
using System.Linq;
using System.Threading;

namespace TinyUa.Core.Logging
{
    internal static class SecurityDebugLogger
    {
        private static readonly AsyncLocal<ILogger?> _current = new();

        internal static ILogger? Current => _current.Value;

        /// <summary>
        /// Installs <paramref name="logger"/> as the ambient security-debug logger for the current
        /// async flow and returns a scope that restores the previous logger when disposed. Use
        /// <c>using var _ = SecurityDebugLogger.BeginScope(logger);</c> instead of manual
        /// save/restore — a forgotten restore leaks the logger into unrelated flows.
        /// </summary>
        internal static LoggerScope BeginScope(ILogger? logger)
        {
            var previous = _current.Value;
            _current.Value = logger;
            return new LoggerScope(previous);
        }

        internal readonly struct LoggerScope : IDisposable
        {
            private readonly ILogger? _previous;
            internal LoggerScope(ILogger? previous) => _previous = previous;
            public void Dispose() => _current.Value = _previous;
        }

        /// <summary>
        /// Gets whether the current ambient logger has Debug logging enabled. Use this to gate
        /// expensive diagnostic-only work (e.g. self-verify round-trips) so it is skipped entirely
        /// when debug logging is off, not merely suppressed at the log call.
        /// </summary>
        internal static bool IsDebugEnabled
        {
            get
            {
                var logger = _current.Value;
                return logger != null && logger.IsEnabled(LogLevel.Debug);
            }
        }

        internal static void LogStage(string stage, params (string key, object? value)[] fields)
        {
            var logger = _current.Value;
            if (logger == null || !logger.IsEnabled(LogLevel.Debug))
                return;

            var kv = fields.Length == 0
                ? ""
                : string.Join(", ", fields.Select(f => $"{f.key}={FormatValue(f.value)}"));
            logger.LogDebug($"[Security] {stage}: {kv}");
        }

        internal static void LogStage(ILogger logger, string stage, params (string key, object? value)[] fields)
        {
            if (!logger.IsEnabled(LogLevel.Debug))
                return;

            var kv = fields.Length == 0
                ? ""
                : string.Join(", ", fields.Select(f => $"{f.key}={FormatValue(f.value)}"));
            logger.LogDebug($"[Security] {stage}: {kv}");
        }

        internal static void LogHexDump(string label, byte[]? data, int maxBytes = 200)
        {
            var logger = _current.Value;
            if (logger == null || !logger.IsEnabled(LogLevel.Debug))
                return;
            LogHexDump(logger, label, data, maxBytes);
        }

        internal static void LogHexDump(ILogger logger, string label, byte[]? data, int maxBytes = 200)
        {
            if (!logger.IsEnabled(LogLevel.Debug))
                return;

            if (data == null || data.Length == 0)
            {
                logger.LogDebug($"[Security] {label}: (null or empty)");
                return;
            }

            int len = Math.Min(data.Length, maxBytes);
            var hex = string.Join(" ", data.Take(len).Select(b => b.ToString("X2")));
            var suffix = data.Length > maxBytes ? $" ... ({data.Length} bytes total)" : "";
            logger.LogDebug($"[Security] {label} ({data.Length} bytes): {hex}{suffix}");
        }

        private static string FormatValue(object? value)
        {
            return value switch
            {
                null => "null",
                byte[] bytes => $"[{bytes.Length} bytes]",
                Array arr => $"[{arr.Length} items]",
                _ => value.ToString() ?? "null"
            };
        }
    }
}
