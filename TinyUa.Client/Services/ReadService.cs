using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Enumerates the OPC UA node attributes that can be read or written.
    /// The numeric values correspond to the OPC UA specification attribute IDs.
    /// </summary>
    public enum AttributeId : uint
    {
        /// <summary>The NodeId attribute.</summary>
        NodeId = 1,
        /// <summary>The NodeClass attribute.</summary>
        NodeClass = 2,
        /// <summary>The BrowseName attribute.</summary>
        BrowseName = 3,
        /// <summary>The DisplayName attribute.</summary>
        DisplayName = 4,
        /// <summary>The Description attribute.</summary>
        Description = 5,
        /// <summary>The WriteMask attribute.</summary>
        WriteMask = 6,
        /// <summary>The UserWriteMask attribute.</summary>
        UserWriteMask = 7,
        /// <summary>The IsAbstract attribute.</summary>
        IsAbstract = 8,
        /// <summary>The Symmetric attribute.</summary>
        Symmetric = 9,
        /// <summary>The InverseName attribute.</summary>
        InverseName = 10,
        /// <summary>The ContainsNoLoops attribute.</summary>
        ContainsNoLoops = 11,
        /// <summary>The EventNotifier attribute.</summary>
        EventNotifier = 12,
        /// <summary>The Value attribute.</summary>
        Value = 13,
        /// <summary>The DataType attribute.</summary>
        DataType = 14,
        /// <summary>The ValueRank attribute.</summary>
        ValueRank = 15,
        /// <summary>The ArrayDimensions attribute.</summary>
        ArrayDimensions = 16,
        /// <summary>The AccessLevel attribute.</summary>
        AccessLevel = 17,
        /// <summary>The UserAccessLevel attribute.</summary>
        UserAccessLevel = 18,
        /// <summary>The MinimumSamplingInterval attribute.</summary>
        MinimumSamplingInterval = 19,
        /// <summary>The Historizing attribute.</summary>
        Historizing = 20,
        /// <summary>The Executable attribute.</summary>
        Executable = 21,
        /// <summary>The UserExecutable attribute.</summary>
        UserExecutable = 22,
        /// <summary>The DataTypeDefinition attribute.</summary>
        DataTypeDefinition = 23,
        /// <summary>The RolePermissions attribute.</summary>
        RolePermissions = 24,
        /// <summary>The UserRolePermissions attribute.</summary>
        UserRolePermissions = 25,
        /// <summary>The AccessRestrictions attribute.</summary>
        AccessRestrictions = 26,
        /// <summary>The AccessLevelEx attribute.</summary>
        AccessLevelEx = 27
    }

    /// <summary>
    /// Specifies a single node and attribute to read in a Read service request.
    /// </summary>
    public class ReadValueId : IEncodable
    {
        /// <summary>
        /// Gets or sets the NodeId of the node to read.
        /// </summary>
        public NodeId NodeId { get; set; } = new NodeId();

        /// <summary>
        /// Gets or sets the attribute to read. Defaults to <see cref="AttributeId.Value"/>.
        /// </summary>
        public AttributeId AttributeId { get; set; } = AttributeId.Value;

        /// <summary>
        /// Gets or sets an optional index range string for reading a portion of an array.
        /// </summary>
        public string? IndexRange { get; set; }

        /// <summary>
        /// Gets or sets an optional data encoding qualified name.
        /// </summary>
        public QualifiedName? DataEncoding { get; set; }

        /// <summary>
        /// Encodes this read value ID into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, NodeId);
            encoder.WriteUInt32((uint)AttributeId);
            encoder.WriteString(IndexRange);
            QualifiedNameCodec.Encode(encoder, DataEncoding);
        }
    }

    /// <summary>
    /// Contains the parameters for a Read service request.
    /// </summary>
    public class ReadParameters : IEncodable
    {
        /// <summary>
        /// Gets or sets the maximum age of cached values to accept, in milliseconds.
        /// 0 means the server must read from the data source.
        /// </summary>
        public double MaxAge { get; set; } = 0;

        /// <summary>
        /// Gets or sets which timestamps to return with each value. Defaults to <see cref="TimestampsToReturn.Both"/>.
        /// </summary>
        public TimestampsToReturn TimestampsToReturn { get; set; } = TimestampsToReturn.Both;

        /// <summary>
        /// Gets or sets the array of nodes and attributes to read.
        /// </summary>
        public ReadValueId[] NodesToRead { get; set; } = Array.Empty<ReadValueId>();

        /// <summary>
        /// Encodes the read parameters into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
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

    /// <summary>
    /// Represents a complete OPC UA Read service request.
    /// </summary>
    public class ReadRequest : IServiceRequest
    {
        /// <summary>
        /// Gets or sets the request header for the service call.
        /// </summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>
        /// Gets or sets the read parameters.
        /// </summary>
        public ReadParameters Parameters { get; set; } = new ReadParameters();

        /// <summary>
        /// Encodes the read request into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(631, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents a response from a Read service call.
    /// </summary>
    public class ReadResponse : IDecodable<ReadResponse>, IServiceResponse
    {
        /// <summary>
        /// Gets or sets the response header containing the service result.
        /// </summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>
        /// Gets or sets the array of data values, one for each read value requested.
        /// </summary>
        public DataValue[]? Results { get; set; }

        /// <summary>
        /// Decodes a <see cref="ReadResponse"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="ReadResponse"/> decoded from the stream.</returns>
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

    /// <summary>
    /// Represents the result of a single node read in a batch <see cref="UaClient.ReadAsync(NodeId[], AttributeId, CancellationToken)"/> call.
    /// </summary>
    public class ReadResult
    {
        /// <summary>The NodeId that was read.</summary>
        public NodeId NodeId { get; init; } = new NodeId();

        /// <summary>The status code for this read. Always present, even if <see cref="DataValue"/> is null.</summary>
        public StatusCode StatusCode { get; init; } = StatusCode.Bad;

        /// <summary>The returned data value, or <c>null</c> if the read failed.</summary>
        public DataValue? DataValue { get; init; }
    }
}
