using TinyUa.Core;
using System;

namespace TinyUa.Client
{
    /// <summary>
    /// Represents errors that occur during UA operation processing.
    /// </summary>
    public class UaOperationException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UaOperationException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public UaOperationException(string message) : base(message) { }
        /// <summary>
        /// Initializes a new instance of the <see cref="UaOperationException"/> class
        /// with a specified error message and a reference to the inner exception
        /// that is the cause of this exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception,
        /// or a null reference if no inner exception is specified.</param>
        public UaOperationException(string message, Exception innerException) : base(message, innerException) { }
    }
}
