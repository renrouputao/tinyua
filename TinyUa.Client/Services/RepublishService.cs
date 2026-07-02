using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{

    public class RepublishParameters : IEncodable
    {
        public uint SubscriptionId { get; set; }
        public uint RetransmitSequenceNumber { get; set; }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteUInt32(RetransmitSequenceNumber);
        }
    }

    public class RepublishRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public RepublishParameters Parameters { get; set; } = new RepublishParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(832, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class RepublishResponse : IDecodable<RepublishResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();
        public NotificationMessage NotificationMessage { get; set; } = new NotificationMessage();

        public static RepublishResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new RepublishResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                NotificationMessage = NotificationMessage.Decode(decoder)
            };

            return response;
        }
    }
}
