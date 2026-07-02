using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public class CloseSecureChannelRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(452, 0));
            RequestHeader.Encode(encoder);
        }
    }
}
