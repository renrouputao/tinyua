using System;

namespace TinyUa.Core.Client
{
    public class UaOperationException : Exception
    {
        public UaOperationException(string message) : base(message) { }
        public UaOperationException(string message, Exception innerException) : base(message, innerException) { }
    }
}
