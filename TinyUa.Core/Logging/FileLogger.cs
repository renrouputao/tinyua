using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TinyUa.Core.Logging
{
    /// <summary>
    /// An <see cref="ILogger"/> implementation that writes log entries to date-based rolling files, with optional asynchronous writing.
    /// </summary>
    public sealed class FileLogger : ILogger, IDisposable
    {
        private readonly string _directory;
        private readonly LogLevel _minLevel;
        private readonly bool _async;
        private readonly object _lock = new();
        private StreamWriter? _writer;
        private string? _currentDate;
        private bool _disposed;

        private readonly ConcurrentQueue<string> _queue = new();
        private readonly SemaphoreSlim _signal = new(0);
        private readonly CancellationTokenSource _cts = new();
        private Task? _writerTask;
        private const int MaxQueueSize = 4096;
        private int _droppedCount;

        /// <summary>
        /// Gets the number of log entries that have been dropped due to a full queue (async mode only).
        /// </summary>
        public int DroppedCount => Volatile.Read(ref _droppedCount);

        /// <summary>
        /// Initializes a new instance of the <see cref="FileLogger"/> class.
        /// </summary>
        /// <param name="directory">The directory where log files will be created.</param>
        /// <param name="minLevel">The minimum <see cref="LogLevel"/> to log. Defaults to <see cref="LogLevel.Debug"/>.</param>
        /// <param name="async">
        /// If <c>true</c>, log entries are written on a background thread using a concurrent queue.
        /// If <c>false</c>, log entries are written synchronously and flushed immediately.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="directory"/> is <c>null</c>.</exception>
        public FileLogger(string directory, LogLevel minLevel = LogLevel.Debug, bool async = false)
        {
            _directory = directory ?? throw new ArgumentNullException(nameof(directory));
            _minLevel = minLevel;
            _async = async;

            if (!Directory.Exists(_directory))
                Directory.CreateDirectory(_directory);

            if (_async)
                _writerTask = Task.Run(WriterLoopAsync);
        }

        /// <inheritdoc />
        public void Log(LogLevel level, Exception? exception, string message)
        {
            if (level < _minLevel) return;

            var line = FormatLine(level, exception, message);

            if (!_async)
            {
                lock (_lock)
                {
                    if (_disposed) return;
                    EnsureWriter();
                    _writer!.WriteLine(line);
                    _writer.Flush();
                }
                return;
            }

            if (_queue.Count >= MaxQueueSize)
            {
                Interlocked.Increment(ref _droppedCount);
                return;
            }

            _queue.Enqueue(line);
            _signal.Release();
        }

        /// <inheritdoc />
        public bool IsEnabled(LogLevel level) => level >= _minLevel;

        private async Task WriterLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    await _signal.WaitAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }

                while (_queue.TryDequeue(out var line))
                {
                    lock (_lock)
                    {
                        if (_disposed) return;
                        EnsureWriter();
                        _writer!.WriteLine(line);
                    }
                }

                lock (_lock)
                {
                    _writer?.Flush();
                }
            }

            while (_queue.TryDequeue(out var line))
            {
                lock (_lock)
                {
                    if (_disposed) break;
                    EnsureWriter();
                    _writer!.WriteLine(line);
                }
            }

            lock (_lock)
            {
                _writer?.Flush();
            }
        }

        private static string FormatLine(LogLevel level, Exception? exception, string message)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
            var levelTag = LevelTag(level);
            var sb = new StringBuilder(128 + (message?.Length ?? 0));
            sb.Append(timestamp).Append(" [").Append(levelTag).Append("] ").Append(message);
            if (exception != null)
                sb.Append(" | ").Append(exception.GetType().Name).Append(": ").Append(exception.Message);
            return sb.ToString();
        }

        private void EnsureWriter()
        {
            var today = DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (_currentDate == today && _writer != null)
                return;

            _writer?.Dispose();
            _currentDate = today;
            var path = Path.Combine(_directory, $"TinyUa_{today}.log");
            _writer = new StreamWriter(path, append: true, new UTF8Encoding(false))
            {
                AutoFlush = false
            };
        }

        private static string LevelTag(LogLevel level) => level switch
        {
            LogLevel.Trace       => "TRC",
            LogLevel.Debug       => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning     => "WRN",
            LogLevel.Error       => "ERR",
            _                    => "???"
        };

        /// <summary>
        /// Releases all resources used by the <see cref="FileLogger"/>, flushing any pending log entries and closing the underlying file stream.
        /// </summary>
        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
            }

            if (_async)
            {

                _cts.Cancel();
                try
                {
                    _writerTask?.Wait(TimeSpan.FromSeconds(5));
                }
                catch { }
                _cts.Dispose();
                _signal.Dispose();
            }

            lock (_lock)
            {
                _writer?.Dispose();
                _writer = null;
            }
        }
    }
}
