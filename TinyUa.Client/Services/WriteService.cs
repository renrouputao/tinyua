using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public class WriteValue : IEncodable
    {
        public NodeId NodeId { get; set; } = new NodeId();
        public uint AttributeId { get; set; } = 13;
        public string? IndexRange { get; set; }
        public DataValue Value { get; set; } = new DataValue();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, NodeId);
            encoder.WriteUInt32(AttributeId);
            encoder.WriteString(IndexRange);
            Value.Encode(encoder);
        }
    }

    public class WriteParameters : IEncodable
    {
        public WriteValue[] NodesToWrite { get; set; } = Array.Empty<WriteValue>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteInt32(NodesToWrite.Length);
            foreach (var node in NodesToWrite)
            {
                node.Encode(encoder);
            }
        }
    }

    public class WriteRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public WriteParameters Parameters { get; set; } = new WriteParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(673, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class WriteResponse : IDecodable<WriteResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public StatusCode[]? Results { get; set; }

        public static WriteResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new WriteResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new StatusCode[count];
                for (int i = 0; i < count; i++)
                {
                    response.Results[i] = new StatusCode(decoder.ReadUInt32());
                }
            }

            decoder.SkipDiagnosticInfos();

            return response;
        }
    }
}
