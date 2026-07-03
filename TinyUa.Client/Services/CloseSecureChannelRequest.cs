using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    /// <summary>
    /// Represents the CloseSecureChannel service request used to close an active secure channel.
    /// </summary>
    public class CloseSecureChannelRequest : IEncodable
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(452, 0));
            RequestHeader.Encode(encoder);
        }
    }
}
