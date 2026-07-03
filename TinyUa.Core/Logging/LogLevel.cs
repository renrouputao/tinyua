namespace TinyUa.Core.Logging
{
    /// <summary>
    /// Defines the severity levels for log messages.
    /// </summary>
    public enum LogLevel
    {
        /// <summary>
        /// Detailed trace information, typically for diagnosing problems during development.
        /// </summary>
        Trace = 0,

        /// <summary>
        /// Debug-level information useful for development and troubleshooting.
        /// </summary>
        Debug = 1,

        /// <summary>
        /// General informational messages that highlight the progress of the application.
        /// </summary>
        Information = 2,

        /// <summary>
        /// Warnings that indicate a potential problem or unexpected condition that does not prevent the application from continuing.
        /// </summary>
        Warning = 3,

        /// <summary>
        /// Errors that indicate a failure condition that must be addressed.
        /// </summary>
        Error = 4,

        /// <summary>
        /// No logging output.
        /// </summary>
        None = 5
    }
}
