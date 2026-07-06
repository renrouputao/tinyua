using TinyUa.Core;
using System;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Logging;

namespace TinyUa.Client
{
    /// <summary>
    /// Provides extension methods for <see cref="Task"/> and <see cref="Task{TResult}"/> instances.
    /// </summary>
    public static class TaskExtensions
    {
        /// <summary>
        /// Launches the task as a fire-and-forget operation, logging any unobserved exceptions to the specified logger.
        /// </summary>
        /// <param name="task">The task to observe.</param>
        /// <param name="logger">The logger used to record errors from the task.</param>
        /// <param name="context">An optional context string included in error messages.</param>
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

        /// <summary>
        /// Waits for the task to complete, throwing a <see cref="TimeoutException"/> if it does not finish within the specified number of milliseconds.
        /// </summary>
        /// <typeparam name="T">The result type of the task.</typeparam>
        /// <param name="task">The task to wait on.</param>
        /// <param name="timeoutMs">The timeout duration in milliseconds. A value of zero or less means no timeout.</param>
        /// <param name="errorMessage">An optional custom error message for the <see cref="TimeoutException"/>.</param>
        /// <returns>The result produced by the task.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="task"/> is <c>null</c>.</exception>
        /// <exception cref="TimeoutException">Thrown when the task does not complete within the specified timeout.</exception>
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

        /// <summary>
        /// Waits for the task to complete, throwing a <see cref="TimeoutException"/> if it does not finish within the specified number of milliseconds.
        /// </summary>
        /// <param name="task">The task to wait on.</param>
        /// <param name="timeoutMs">The timeout duration in milliseconds. A value of zero or less means no timeout.</param>
        /// <param name="errorMessage">An optional custom error message for the <see cref="TimeoutException"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="task"/> is <c>null</c>.</exception>
        /// <exception cref="TimeoutException">Thrown when the task does not complete within the specified timeout.</exception>
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

        /// <summary>
        /// Waits for the task to complete, returning its integer result. Throws a <see cref="TimeoutException"/> if it does not finish within the specified number of milliseconds.
        /// </summary>
        /// <param name="task">The task to wait on.</param>
        /// <param name="timeoutMs">The timeout duration in milliseconds. A value of zero or less means no timeout.</param>
        /// <param name="errorMessage">An optional custom error message for the <see cref="TimeoutException"/>.</param>
        /// <returns>The integer result produced by the task.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="task"/> is <c>null</c>.</exception>
        /// <exception cref="TimeoutException">Thrown when the task does not complete within the specified timeout.</exception>
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
