using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Parameters for the DeleteSubscriptions service request.
    /// </summary>
    public class DeleteSubscriptionsParameters : IEncodable
    {
        /// <summary>Gets or sets the array of subscription identifiers to delete.</summary>
        public uint[] SubscriptionIds { get; set; } = Array.Empty<uint>();

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteArray(SubscriptionIds, (BinaryEncoder e, uint id) => e.WriteUInt32(id));
        }
    }

    /// <summary>
    /// Represents the DeleteSubscriptions service request used to remove subscriptions from the server.
    /// </summary>
    public class DeleteSubscriptionsRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the DeleteSubscriptions parameters.</summary>
        public DeleteSubscriptionsParameters Parameters { get; set; } = new DeleteSubscriptionsParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(847, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the DeleteSubscriptions service response returned by the server.
    /// </summary>
    public class DeleteSubscriptionsResponse : IDecodable<DeleteSubscriptionsResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        /// <summary>Gets or sets the array of status codes, one for each subscription to delete.</summary>
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

        /// <summary>
        /// Decodes a <see cref="DeleteSubscriptionsResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="DeleteSubscriptionsResponse"/>.</returns>
        public static DeleteSubscriptionsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new DeleteSubscriptionsResponse
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
