using System;

namespace TinyUa.Core.Logging
{
    public interface ILogger
    {
        void Log(LogLevel level, Exception? exception, string message);
        bool IsEnabled(LogLevel level);
    }
}
