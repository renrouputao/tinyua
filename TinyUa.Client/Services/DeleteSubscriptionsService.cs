using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{

    public class DeleteSubscriptionsParameters : IEncodable
    {
        public uint[] SubscriptionIds { get; set; } = Array.Empty<uint>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteArray(SubscriptionIds, (BinaryEncoder e, uint id) => e.WriteUInt32(id));
        }
    }

    public class DeleteSubscriptionsRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public DeleteSubscriptionsParameters Parameters { get; set; } = new DeleteSubscriptionsParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(847, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class DeleteSubscriptionsResponse : IDecodable<DeleteSubscriptionsResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

        public static DeleteSubscriptionsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new DeleteSubscriptionsResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new StatusCode[count];
                for (int i = 0; i < count; i++)
                    response.Results[i] = new StatusCode(decoder.ReadUInt32());
            }

            decoder.SkipDiagnosticInfos();
            return response;
        }
    }
}
