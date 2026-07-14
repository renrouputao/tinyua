using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Parameters for the DeleteMonitoredItems service request.
    /// </summary>
    public class DeleteMonitoredItemsParameters : IEncodable
    {
        /// <summary>Gets or sets the subscription identifier containing the monitored items to delete.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the array of monitored item identifiers to delete.</summary>
        public uint[] MonitoredItemIds { get; set; } = Array.Empty<uint>();

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteArray(MonitoredItemIds, (BinaryEncoder e, uint id) => e.WriteUInt32(id));
        }
    }

    /// <summary>
    /// Represents the DeleteMonitoredItems service request used to remove monitored items from a subscription.
    /// </summary>
    public class DeleteMonitoredItemsRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the DeleteMonitoredItems parameters.</summary>
        public DeleteMonitoredItemsParameters Parameters { get; set; } = new DeleteMonitoredItemsParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(781, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the DeleteMonitoredItems service response returned by the server.
    /// </summary>
    public class DeleteMonitoredItemsResponse : IDecodable<DeleteMonitoredItemsResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        /// <summary>Gets or sets the array of status codes, one for each monitored item to delete.</summary>
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

        /// <summary>
        /// Decodes a <see cref="DeleteMonitoredItemsResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="DeleteMonitoredItemsResponse"/>.</returns>
        public static DeleteMonitoredItemsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new DeleteMonitoredItemsResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadArrayLength();
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
