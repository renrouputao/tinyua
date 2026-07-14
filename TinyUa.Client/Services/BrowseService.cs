using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Specifies the direction of a browse operation in the OPC UA address space.
    /// </summary>
    public enum BrowseDirection
    {
        /// <summary>Browse forward (follow references from source to target).</summary>
        Forward = 0,
        /// <summary>Browse inverse (follow references from target to source).</summary>
        Inverse = 1,
        /// <summary>Browse in both directions.</summary>
        Both = 2,
        /// <summary>Invalid direction.</summary>
        Invalid = 3
    }

    /// <summary>
    /// Specifies which timestamps to return in a read or browse response.
    /// </summary>
    public enum TimestampsToReturn
    {
        /// <summary>Return only the source timestamp.</summary>
        Source = 0,
        /// <summary>Return only the server timestamp.</summary>
        Server = 1,
        /// <summary>Return both source and server timestamps.</summary>
        Both = 2,
        /// <summary>Return no timestamps.</summary>
        Neither = 3,
        /// <summary>Invalid / unspecified.</summary>
        Invalid = 4
    }

    /// <summary>
    /// Describes a View in the OPC UA address space used to scope a browse operation.
    /// </summary>
    public class ViewDescription : IEncodable
    {
        /// <summary>
        /// Gets or sets the NodeId of the view.
        /// </summary>
        public NodeId ViewId { get; set; } = new NodeId();

        /// <summary>
        /// Gets or sets the timestamp of the view.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.MinValue;

        /// <summary>
        /// Gets or sets the version of the view.
        /// </summary>
        public uint ViewVersion { get; set; } = 0;

        /// <summary>
        /// Encodes this view description into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, ViewId);
            encoder.WriteDateTime(Timestamp);
            encoder.WriteUInt32(ViewVersion);
        }
    }

    /// <summary>
    /// Describes a single browse request for a node in the OPC UA address space.
    /// </summary>
    public class BrowseDescription : IEncodable
    {
        /// <summary>
        /// Gets or sets the NodeId of the node to browse.
        /// </summary>
        public NodeId NodeId { get; set; } = new NodeId();

        /// <summary>
        /// Gets or sets the browse direction.
        /// </summary>
        public BrowseDirection BrowseDirection { get; set; } = BrowseDirection.Forward;

        /// <summary>
        /// Gets or sets the reference type to filter by. Defaults to HierarchicalReferences (i=33).
        /// </summary>
        public NodeId ReferenceTypeId { get; set; } = new NodeId(33, 0);

        /// <summary>
        /// Gets or sets whether to include subtypes of the <see cref="ReferenceTypeId"/>.
        /// </summary>
        public bool IncludeSubtypes { get; set; } = true;

        /// <summary>
        /// Gets or sets a bitmask of <see cref="NodeClass"/> values to filter results.
        /// </summary>
        public uint NodeClassMask { get; set; } = 0;

        /// <summary>
        /// Gets or sets a bitmask specifying which fields to return in the results.
        /// Defaults to 63 (all fields).
        /// </summary>
        public uint ResultMask { get; set; } = 63;

        /// <summary>
        /// Encodes this browse description into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
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

    /// <summary>
    /// Contains the parameters for a Browse service request.
    /// </summary>
    public class BrowseParameters : IEncodable
    {
        /// <summary>
        /// Gets or sets the view description to scope the browse.
        /// </summary>
        public ViewDescription View { get; set; } = new ViewDescription();

        /// <summary>
        /// Gets or sets the maximum number of references to return per node. Defaults to 1000.
        /// </summary>
        public uint RequestedMaxReferencesPerNode { get; set; } = 1000;

        /// <summary>
        /// Gets or sets the array of browse descriptions for nodes to browse.
        /// </summary>
        public BrowseDescription[] NodesToBrowse { get; set; } = Array.Empty<BrowseDescription>();

        /// <summary>
        /// Encodes the browse parameters into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
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

    /// <summary>
    /// Represents a complete OPC UA Browse service request.
    /// </summary>
    public class BrowseRequest : IServiceRequest
    {
        /// <summary>
        /// Gets or sets the request header for the service call.
        /// </summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>
        /// Gets or sets the browse parameters.
        /// </summary>
        public BrowseParameters Parameters { get; set; } = new BrowseParameters();

        /// <summary>
        /// Encodes the browse request into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(527, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Describes a single reference returned by a Browse operation.
    /// </summary>
    public class ReferenceDescription : IDecodable<ReferenceDescription>
    {
        /// <summary>
        /// Gets or sets the NodeId of the reference type.
        /// </summary>
        public NodeId ReferenceTypeId { get; set; } = new NodeId();

        /// <summary>
        /// Gets or sets whether the reference is forward (from source to target).
        /// </summary>
        public bool IsForward { get; set; }

        /// <summary>
        /// Gets or sets the target NodeId of the reference.
        /// </summary>
        public ExpandedNodeId NodeId { get; set; } = new ExpandedNodeId();

        /// <summary>
        /// Gets or sets the browse name of the target node.
        /// </summary>
        public QualifiedName? BrowseName { get; set; }

        /// <summary>
        /// Gets or sets the display name of the target node.
        /// </summary>
        public LocalizedText? DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the node class of the target node.
        /// </summary>
        public NodeClass NodeClass { get; set; }

        /// <summary>
        /// Gets or sets the type definition of the target node.
        /// </summary>
        public ExpandedNodeId TypeDefinition { get; set; } = new ExpandedNodeId();

        /// <summary>
        /// Decodes a <see cref="ReferenceDescription"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="ReferenceDescription"/> decoded from the stream.</returns>
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

    /// <summary>
    /// Contains the result of browsing a single node.
    /// </summary>
    public class BrowseResult : IDecodable<BrowseResult>
    {
        /// <summary>
        /// Gets or sets the status code for the browse operation on this node.
        /// </summary>
        public StatusCode StatusCode { get; set; } = new StatusCode();

        /// <summary>
        /// Gets or sets a continuation point for paged results, or null if results are complete.
        /// </summary>
        public byte[]? ContinuationPoint { get; set; }

        /// <summary>
        /// Gets or sets the array of reference descriptions returned for this node.
        /// </summary>
        public ReferenceDescription[]? References { get; set; }

        /// <summary>
        /// Decodes a <see cref="BrowseResult"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="BrowseResult"/> decoded from the stream.</returns>
        public static BrowseResult Decode(BinaryDecoder decoder)
        {
            var result = new BrowseResult
            {
                StatusCode = new StatusCode(decoder.ReadUInt32()),
                ContinuationPoint = decoder.ReadByteString()
            };

            var count = decoder.ReadArrayLength();
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

    /// <summary>
    /// Represents a response from a Browse service call.
    /// </summary>
    public class BrowseResponse : IDecodable<BrowseResponse>, IServiceResponse
    {
        /// <summary>
        /// Gets or sets the response header containing the service result.
        /// </summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>
        /// Gets or sets the array of browse results, one for each node requested.
        /// </summary>
        public BrowseResult[]? Results { get; set; }

        /// <summary>
        /// Decodes a <see cref="BrowseResponse"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="BrowseResponse"/> decoded from the stream.</returns>
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

    /// <summary>
    /// Represents a BrowseNext service request, used to retrieve additional results when
    /// a previous Browse operation returned continuation points.
    /// </summary>
    public class BrowseNextRequest : IServiceRequest
    {
        /// <summary>
        /// Gets or sets the request header for the service call.
        /// </summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>
        /// Gets or sets whether to release the continuation points without returning results.
        /// </summary>
        public bool ReleaseContinuationPoints { get; set; } = false;

        /// <summary>
        /// Gets or sets the continuation points from a previous Browse response.
        /// </summary>
        public byte[][] ContinuationPoints { get; set; } = Array.Empty<byte[]>();

        /// <summary>
        /// Encodes the BrowseNext request into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
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

    /// <summary>
    /// Represents a response from a BrowseNext service call.
    /// </summary>
    public class BrowseNextResponse : IDecodable<BrowseNextResponse>, IServiceResponse
    {
        /// <summary>
        /// Gets or sets the response header containing the service result.
        /// </summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>
        /// Gets or sets the array of browse results for the continued browse operations.
        /// </summary>
        public BrowseResult[]? Results { get; set; }

        /// <summary>
        /// Decodes a <see cref="BrowseNextResponse"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="BrowseNextResponse"/> decoded from the stream.</returns>
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
