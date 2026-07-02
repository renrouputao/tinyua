using System;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;

namespace TinyUa.Core.Client
{
    public static class TaskExtensions
    {

        public static void Forget(this Task task, ILogger logger, string context = "")
        {
            _ = ObserveAsync(task, logger, context);
        }

        private static async Task ObserveAsync(Task task, ILogger logger, string context)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Fire-and-forget task failed: {context}");
            }
        }
        public static async Task<T> WithTimeout<T>(this Task<T> task, int timeoutMs, string? errorMessage = null)
        {
            if (task == null)
                throw new ArgumentNullException(nameof(task));

            if (timeoutMs <= 0)
                return await task.ConfigureAwait(false);

            try
            {
                return await task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(errorMessage ?? $"Operation timed out after {timeoutMs}ms");
            }
        }

        public static async Task WithTimeout(this Task task, int timeoutMs, string? errorMessage = null)
        {
            if (task == null)
                throw new ArgumentNullException(nameof(task));

            if (timeoutMs <= 0)
            {
                await task.ConfigureAwait(false);
                return;
            }

            try
            {
                await task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(errorMessage ?? $"Operation timed out after {timeoutMs}ms");
            }
        }

        public static async Task<int> WithTimeout(this Task<int> task, int timeoutMs, string? errorMessage = null)
        {
            if (task == null)
                throw new ArgumentNullException(nameof(task));

            if (timeoutMs <= 0)
                return await task.ConfigureAwait(false);

            try
            {
                return await task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(errorMessage ?? $"Operation timed out after {timeoutMs}ms");
            }
        }
    }
}
