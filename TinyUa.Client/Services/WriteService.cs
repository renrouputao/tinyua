using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Specifies a single node, attribute, and value to write in a Write service request.
    /// </summary>
    public class WriteValue : IEncodable
    {
        /// <summary>
        /// Gets or sets the NodeId of the node to write.
        /// </summary>
        public NodeId NodeId { get; set; } = new NodeId();

        /// <summary>
        /// Gets or sets the attribute ID to write. Defaults to 13 (<see cref="AttributeId.Value"/>).
        /// </summary>
        public uint AttributeId { get; set; } = 13;

        /// <summary>
        /// Gets or sets an optional index range string for writing a portion of an array.
        /// </summary>
        public string? IndexRange { get; set; }

        /// <summary>
        /// Gets or sets the data value to write, including the variant value and optional status/timestamps.
        /// </summary>
        public DataValue Value { get; set; } = new DataValue();

        /// <summary>
        /// Encodes this write value into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, NodeId);
            encoder.WriteUInt32(AttributeId);
            encoder.WriteString(IndexRange);
            Value.Encode(encoder);
        }
    }

    /// <summary>
    /// Contains the parameters for a Write service request.
    /// </summary>
    public class WriteParameters : IEncodable
    {
        /// <summary>
        /// Gets or sets the array of nodes and values to write.
        /// </summary>
        public WriteValue[] NodesToWrite { get; set; } = Array.Empty<WriteValue>();

        /// <summary>
        /// Encodes the write parameters into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteInt32(NodesToWrite.Length);
            foreach (var node in NodesToWrite)
            {
                node.Encode(encoder);
            }
        }
    }

    /// <summary>
    /// Represents a complete OPC UA Write service request.
    /// </summary>
    public class WriteRequest : IEncodable
    {
        /// <summary>
        /// Gets or sets the request header for the service call.
        /// </summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>
        /// Gets or sets the write parameters.
        /// </summary>
        public WriteParameters Parameters { get; set; } = new WriteParameters();

        /// <summary>
        /// Encodes the write request into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(673, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents a response from a Write service call.
    /// </summary>
    public class WriteResponse : IDecodable<WriteResponse>
    {
        /// <summary>
        /// Gets or sets the response header containing the service result.
        /// </summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>
        /// Gets or sets the array of status codes, one for each node written.
        /// </summary>
        public StatusCode[]? Results { get; set; }

        /// <summary>
        /// Decodes a <see cref="WriteResponse"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="WriteResponse"/> decoded from the stream.</returns>
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

    /// <summary>
    /// Represents the result of a single node write in a batch <see cref="UaClient.WriteAsync(WriteValue[], CancellationToken)"/> call.
    /// </summary>
    public class WriteResult
    {
        /// <summary>The NodeId that was written.</summary>
        public NodeId NodeId { get; init; } = new NodeId();

        /// <summary>The status code returned by the server for this write.</summary>
        public StatusCode StatusCode { get; init; }
    }
}
