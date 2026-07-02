using System;

namespace TinyUa.Core.Logging
{

    public sealed class DelegateLogger : ILogger
    {
        private readonly Action<LogLevel, Exception?, string> _sink;
        private readonly LogLevel _minLevel;

        public DelegateLogger(Action<LogLevel, Exception?, string> sink, LogLevel minLevel = LogLevel.Debug)
        {
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _minLevel = minLevel;
        }

        public void Log(LogLevel level, Exception? exception, string message)
        {
            if (level < _minLevel) return;
            _sink(level, exception, message);
        }

        public bool IsEnabled(LogLevel level) => level >= _minLevel;
    }
}
