using System;
using System.Linq;
using System.Threading;

namespace TinyUa.Core.Logging
{
    internal static class SecurityDebugLogger
    {
        private static readonly AsyncLocal<ILogger?> _current = new();

        internal static ILogger? Current => _current.Value;

        internal static void SetCurrentLogger(ILogger? logger) => _current.Value = logger;

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
