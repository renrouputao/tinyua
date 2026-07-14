using TinyUa.Core;
using System;
using System.Collections.Generic;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Represents an acknowledgement of a notification received for a subscription.
    /// </summary>
    public class SubscriptionAcknowledgement : IEncodable
    {
        /// <summary>Gets or sets the subscription identifier being acknowledged.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the sequence number of the notification being acknowledged.</summary>
        public uint SequenceNumber { get; set; }

        /// <summary>
        /// Encodes this acknowledgement into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteUInt32(SequenceNumber);
        }
    }

    /// <summary>
    /// Parameters for the Publish service request.
    /// </summary>
    public class PublishParameters : IEncodable
    {
        /// <summary>Gets or sets the array of subscription acknowledgements for previously received notifications.</summary>
        public SubscriptionAcknowledgement[] SubscriptionAcknowledgements { get; set; } = Array.Empty<SubscriptionAcknowledgement>();

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteInt32(SubscriptionAcknowledgements.Length);
            foreach (var ack in SubscriptionAcknowledgements)
            {
                ack.Encode(encoder);
            }
        }
    }

    /// <summary>
    /// Represents the Publish service request used to poll for notifications from the server.
    /// </summary>
    public class PublishRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the Publish parameters.</summary>
        public PublishParameters Parameters { get; set; } = new PublishParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(826, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents a single notification for a monitored item value change.
    /// </summary>
    public class MonitoredItemNotification
    {
        /// <summary>Gets or sets the client-assigned handle identifying the monitored item.</summary>
        public uint ClientHandle { get; set; }

        /// <summary>Gets or sets the data value containing the changed value and its metadata.</summary>
        public DataValue? Value { get; set; }

        /// <summary>
        /// Decodes a <see cref="MonitoredItemNotification"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="MonitoredItemNotification"/>.</returns>
        public static MonitoredItemNotification Decode(BinaryDecoder decoder)
        {
            var notification = new MonitoredItemNotification();
            notification.ClientHandle = decoder.ReadUInt32();
            notification.Value = DataValue.Decode(decoder);
            return notification;
        }
    }

    /// <summary>
    /// Contains a list of data change notifications for one subscription.
    /// </summary>
    public class DataChangeNotificationData
    {
        /// <summary>Gets or sets the list of monitored item notifications.</summary>
        public List<MonitoredItemNotification> Notifications { get; set; } = new List<MonitoredItemNotification>();

        /// <summary>
        /// Decodes a <see cref="DataChangeNotificationData"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="DataChangeNotificationData"/>.</returns>
        public static DataChangeNotificationData Decode(BinaryDecoder decoder)
        {
            var data = new DataChangeNotificationData();
            var count = decoder.ReadInt32();
            for (int i = 0; i < count; i++)
            {
                data.Notifications.Add(MonitoredItemNotification.Decode(decoder));
            }
            return data;
        }
    }

    /// <summary>
    /// Represents a notification message containing one or more notification data entries for a subscription.
    /// </summary>
    public class NotificationMessage
    {
        /// <summary>Gets or sets the monotonically increasing sequence number for detecting lost messages.</summary>
        public uint SequenceNumber { get; set; }

        /// <summary>Gets or sets the timestamp when the notification was published.</summary>
        public DateTime PublishTime { get; set; }

        /// <summary>Gets or sets the list of notification data extension objects (e.g., data change notifications, event notifications).</summary>
        public List<ExtensionObject> NotificationData { get; set; } = new List<ExtensionObject>();

        /// <summary>
        /// Decodes a <see cref="NotificationMessage"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="NotificationMessage"/>.</returns>
        public static NotificationMessage Decode(BinaryDecoder decoder)
        {
            var message = new NotificationMessage();
            message.SequenceNumber = decoder.ReadUInt32();
            message.PublishTime = decoder.ReadDateTime();
            var count = decoder.ReadArrayLength();
            for (int i = 0; i < count; i++)
            {
                message.NotificationData.Add(ExtensionObject.Decode(decoder));
            }
            return message;
        }
    }

    /// <summary>
    /// Represents the result of a single subscription in a Publish response.
    /// </summary>
    public class PublishResult
    {
        /// <summary>Gets or sets the subscription identifier.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the list of available sequence numbers for republishing.</summary>
        public uint[] AvailableSequenceNumbers { get; set; } = Array.Empty<uint>();

        /// <summary>Gets or sets whether more notifications are available beyond this publish response.</summary>
        public bool MoreNotifications { get; set; }

        /// <summary>Gets or sets the notification message containing the actual data.</summary>
        public NotificationMessage NotificationMessage { get; set; } = new NotificationMessage();

        /// <summary>Gets or sets the array of operation status codes for each notification in the message.</summary>
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

        /// <summary>
        /// Decodes a <see cref="PublishResult"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="PublishResult"/>.</returns>
        public static PublishResult Decode(BinaryDecoder decoder)
        {
            var result = new PublishResult();
            result.SubscriptionId = decoder.ReadUInt32();
            var availableCount = decoder.ReadInt32();
            result.AvailableSequenceNumbers = availableCount > 0 ? new uint[availableCount] : Array.Empty<uint>();
            for (int i = 0; i < availableCount; i++)
            {
                result.AvailableSequenceNumbers[i] = decoder.ReadUInt32();
            }
            result.MoreNotifications = decoder.ReadBoolean();
            result.NotificationMessage = NotificationMessage.Decode(decoder);
            var resultsCount = decoder.ReadArrayLength();
            result.Results = resultsCount > 0 ? new StatusCode[resultsCount] : Array.Empty<StatusCode>();
            for (int i = 0; i < resultsCount; i++)
            {
                result.Results[i] = new StatusCode(decoder.ReadUInt32());
            }
            return result;
        }
    }

    /// <summary>
    /// Represents the Publish service response returned by the server containing notification data.
    /// </summary>
    public class PublishResponse : IDecodable<PublishResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        /// <summary>Gets or sets the Publish result containing the subscription notification data.</summary>
        public PublishResult Parameters { get; set; } = new PublishResult();

        /// <summary>
        /// Decodes a <see cref="PublishResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="PublishResponse"/>.</returns>
        public static PublishResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new PublishResponse();
            response.ResponseHeader = ResponseHeader.Decode(decoder);
            response.Parameters = PublishResult.Decode(decoder);
            return response;
        }
    }
}
