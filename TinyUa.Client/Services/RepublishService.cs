using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Parameters for the Republish service request.
    /// </summary>
    public class RepublishParameters : IEncodable
    {
        /// <summary>Gets or sets the subscription identifier to republish notifications from.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the sequence number to retransmit from.</summary>
        public uint RetransmitSequenceNumber { get; set; }

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteUInt32(RetransmitSequenceNumber);
        }
    }

    /// <summary>
    /// Represents the Republish service request used to request retransmission of previously published notifications.
    /// </summary>
    public class RepublishRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the Republish parameters.</summary>
        public RepublishParameters Parameters { get; set; } = new RepublishParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(832, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the Republish service response returned by the server containing the retransmitted notification.
    /// </summary>
    public class RepublishResponse : IDecodable<RepublishResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        /// <summary>Gets or sets the republished notification message.</summary>
        public NotificationMessage NotificationMessage { get; set; } = new NotificationMessage();

        /// <summary>
        /// Decodes a <see cref="RepublishResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="RepublishResponse"/>.</returns>
        public static RepublishResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new RepublishResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                NotificationMessage = NotificationMessage.Decode(decoder)
            };

            return response;
        }
    }
}
