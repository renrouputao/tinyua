using System;

namespace TinyUa.Core.Logging
{
    public sealed class NullLogger : ILogger
    {
        public static readonly NullLogger Instance = new();

        private NullLogger() { }

        public void Log(LogLevel level, Exception? exception, string message) { }
        public bool IsEnabled(LogLevel level) => false;
    }
}
