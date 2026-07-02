using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{

    public class DeleteMonitoredItemsParameters : IEncodable
    {
        public uint SubscriptionId { get; set; }
        public uint[] MonitoredItemIds { get; set; } = Array.Empty<uint>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteArray(MonitoredItemIds, (BinaryEncoder e, uint id) => e.WriteUInt32(id));
        }
    }

    public class DeleteMonitoredItemsRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public DeleteMonitoredItemsParameters Parameters { get; set; } = new DeleteMonitoredItemsParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(781, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class DeleteMonitoredItemsResponse : IDecodable<DeleteMonitoredItemsResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

        public static DeleteMonitoredItemsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new DeleteMonitoredItemsResponse
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
