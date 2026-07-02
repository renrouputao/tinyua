using System;

namespace TinyUa.Core.Client
{
    public class UaConnectionException : Exception
    {
        public UaConnectionException(string message) : base(message) { }
        public UaConnectionException(string message, Exception innerException) : base(message, innerException) { }
    }
}
