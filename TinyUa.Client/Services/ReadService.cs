using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public enum AttributeId : uint
    {
        NodeId = 1,
        NodeClass = 2,
        BrowseName = 3,
        DisplayName = 4,
        Description = 5,
        WriteMask = 6,
        UserWriteMask = 7,
        IsAbstract = 8,
        Symmetric = 9,
        InverseName = 10,
        ContainsNoLoops = 11,
        EventNotifier = 12,
        Value = 13,
        DataType = 14,
        ValueRank = 15,
        ArrayDimensions = 16,
        AccessLevel = 17,
        UserAccessLevel = 18,
        MinimumSamplingInterval = 19,
        Historizing = 20,
        Executable = 21,
        UserExecutable = 22,
        DataTypeDefinition = 23,
        RolePermissions = 24,
        UserRolePermissions = 25,
        AccessRestrictions = 26,
        AccessLevelEx = 27
    }

    public class ReadValueId : IEncodable
    {
        public NodeId NodeId { get; set; } = new NodeId();
        public AttributeId AttributeId { get; set; } = AttributeId.Value;
        public string? IndexRange { get; set; }
        public QualifiedName? DataEncoding { get; set; }

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, NodeId);
            encoder.WriteUInt32((uint)AttributeId);
            encoder.WriteString(IndexRange);
            QualifiedNameCodec.Encode(encoder, DataEncoding);
        }
    }

    public class ReadParameters : IEncodable
    {
        public double MaxAge { get; set; } = 0;
        public TimestampsToReturn TimestampsToReturn { get; set; } = TimestampsToReturn.Both;
        public ReadValueId[] NodesToRead { get; set; } = Array.Empty<ReadValueId>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteDouble(MaxAge);
            encoder.WriteUInt32((uint)TimestampsToReturn);
            encoder.WriteInt32(NodesToRead.Length);
            foreach (var node in NodesToRead)
            {
                node.Encode(encoder);
            }
        }
    }

    public class ReadRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public ReadParameters Parameters { get; set; } = new ReadParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(631, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class ReadResponse : IDecodable<ReadResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public DataValue[]? Results { get; set; }

        public static ReadResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();
            var response = new ReadResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new DataValue[count];
                for (int i = 0; i < count; i++)
                {
                    response.Results[i] = DataValue.Decode(decoder);
                }
            }

            return response;
        }
    }
}
