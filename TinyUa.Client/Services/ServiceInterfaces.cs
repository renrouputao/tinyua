using TinyUa.Core;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// A service request carrying a standard OPC UA request header. Implemented by all
    /// session-level request types so the connection layer can fill the header (authentication
    /// token, timestamp, request handle, timeout hint) in one place.
    /// </summary>
    public interface IServiceRequest : IEncodable
    {
        /// <summary>Gets or sets the standard request header.</summary>
        RequestHeader RequestHeader { get; set; }
    }

    /// <summary>
    /// A service response carrying a standard OPC UA response header, so the connection layer
    /// can check the service result uniformly.
    /// </summary>
    public interface IServiceResponse
    {
        /// <summary>Gets the standard response header.</summary>
        ResponseHeader ResponseHeader { get; }
    }
}
