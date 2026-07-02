using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public enum BrowseDirection
    {
        Forward = 0,
        Inverse = 1,
        Both = 2,
        Invalid = 3
    }

    public enum TimestampsToReturn
    {
        Source = 0,
        Server = 1,
        Both = 2,
        Neither = 3,
        Invalid = 4
    }

    public class ViewDescription : IEncodable
    {
        public NodeId ViewId { get; set; } = new NodeId();
        public DateTime Timestamp { get; set; } = DateTime.MinValue;
        public uint ViewVersion { get; set; } = 0;

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, ViewId);
            encoder.WriteDateTime(Timestamp);
            encoder.WriteUInt32(ViewVersion);
        }
    }

    public class BrowseDescription : IEncodable
    {
        public NodeId NodeId { get; set; } = new NodeId();
        public BrowseDirection BrowseDirection { get; set; } = BrowseDirection.Forward;
        public NodeId ReferenceTypeId { get; set; } = new NodeId(33, 0);
        public bool IncludeSubtypes { get; set; } = true;
        public uint NodeClassMask { get; set; } = 0;
        public uint ResultMask { get; set; } = 63;

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, NodeId);
            encoder.WriteUInt32((uint)BrowseDirection);
            NodeIdCodec.Encode(encoder, ReferenceTypeId);
            encoder.WriteBoolean(IncludeSubtypes);
            encoder.WriteUInt32(NodeClassMask);
            encoder.WriteUInt32(ResultMask);
        }
    }

    public class BrowseParameters : IEncodable
    {
        public ViewDescription View { get; set; } = new ViewDescription();
        public uint RequestedMaxReferencesPerNode { get; set; } = 1000;
        public BrowseDescription[] NodesToBrowse { get; set; } = Array.Empty<BrowseDescription>();

        public void Encode(BinaryEncoder encoder)
        {
            View.Encode(encoder);
            encoder.WriteUInt32(RequestedMaxReferencesPerNode);
            encoder.WriteInt32(NodesToBrowse.Length);
            foreach (var node in NodesToBrowse)
            {
                node.Encode(encoder);
            }
        }
    }

    public class BrowseRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public BrowseParameters Parameters { get; set; } = new BrowseParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(527, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class ReferenceDescription : IDecodable<ReferenceDescription>
    {
        public NodeId ReferenceTypeId { get; set; } = new NodeId();
        public bool IsForward { get; set; }
        public ExpandedNodeId NodeId { get; set; } = new ExpandedNodeId();
        public QualifiedName? BrowseName { get; set; }
        public LocalizedText? DisplayName { get; set; }
        public NodeClass NodeClass { get; set; }
        public ExpandedNodeId TypeDefinition { get; set; } = new ExpandedNodeId();

        public static ReferenceDescription Decode(BinaryDecoder decoder)
        {
            return new ReferenceDescription
            {
                ReferenceTypeId = NodeIdCodec.Decode(decoder),
                IsForward = decoder.ReadBoolean(),
                NodeId = ExpandedNodeIdCodec.Decode(decoder),
                BrowseName = QualifiedNameCodec.Decode(decoder),
                DisplayName = LocalizedTextCodec.Decode(decoder),
                NodeClass = (NodeClass)decoder.ReadInt32(),
                TypeDefinition = ExpandedNodeIdCodec.Decode(decoder)
            };
        }
    }

    public class BrowseResult : IDecodable<BrowseResult>
    {
        public StatusCode StatusCode { get; set; } = new StatusCode();
        public byte[]? ContinuationPoint { get; set; }
        public ReferenceDescription[]? References { get; set; }

        public static BrowseResult Decode(BinaryDecoder decoder)
        {
            var result = new BrowseResult
            {
                StatusCode = new StatusCode(decoder.ReadUInt32()),
                ContinuationPoint = decoder.ReadByteString()
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                result.References = new ReferenceDescription[count];
                for (int i = 0; i < count; i++)
                {
                    result.References[i] = ReferenceDescription.Decode(decoder);
                }
            }

            return result;
        }
    }

    public class BrowseResponse : IDecodable<BrowseResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public BrowseResult[]? Results { get; set; }

        public static BrowseResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new BrowseResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new BrowseResult[count];
                for (int i = 0; i < count; i++)
                {
                    response.Results[i] = BrowseResult.Decode(decoder);
                }
            }

            decoder.SkipDiagnosticInfos();

            return response;
        }
    }

    public class BrowseNextRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public bool ReleaseContinuationPoints { get; set; } = false;
        public byte[][] ContinuationPoints { get; set; } = Array.Empty<byte[]>();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(533, 0));
            RequestHeader.Encode(encoder);
            encoder.WriteBoolean(ReleaseContinuationPoints);
            encoder.WriteInt32(ContinuationPoints.Length);
            foreach (var cp in ContinuationPoints)
            {
                encoder.WriteByteString(cp);
            }
        }
    }

    public class BrowseNextResponse : IDecodable<BrowseNextResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public BrowseResult[]? Results { get; set; }

        public static BrowseNextResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new BrowseNextResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new BrowseResult[count];
                for (int i = 0; i < count; i++)
                {
                    response.Results[i] = BrowseResult.Decode(decoder);
                }
            }

            decoder.SkipDiagnosticInfos();

            return response;
        }
    }
}
