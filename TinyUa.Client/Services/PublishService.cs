using System;
using System.Collections.Generic;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public class SubscriptionAcknowledgement : IEncodable
    {
        public uint SubscriptionId { get; set; }
        public uint SequenceNumber { get; set; }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteUInt32(SequenceNumber);
        }
    }

    public class PublishParameters : IEncodable
    {
        public SubscriptionAcknowledgement[] SubscriptionAcknowledgements { get; set; } = Array.Empty<SubscriptionAcknowledgement>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteInt32(SubscriptionAcknowledgements.Length);
            foreach (var ack in SubscriptionAcknowledgements)
            {
                ack.Encode(encoder);
            }
        }
    }

    public class PublishRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public PublishParameters Parameters { get; set; } = new PublishParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(826, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class MonitoredItemNotification
    {
        public uint ClientHandle { get; set; }
        public DataValue? Value { get; set; }

        public static MonitoredItemNotification Decode(BinaryDecoder decoder)
        {
            var notification = new MonitoredItemNotification();
            notification.ClientHandle = decoder.ReadUInt32();
            notification.Value = DataValue.Decode(decoder);
            return notification;
        }
    }

    public class DataChangeNotificationData
    {
        public List<MonitoredItemNotification> Notifications { get; set; } = new List<MonitoredItemNotification>();

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

    public class NotificationMessage
    {
        public uint SequenceNumber { get; set; }
        public DateTime PublishTime { get; set; }
        public List<ExtensionObject> NotificationData { get; set; } = new List<ExtensionObject>();

        public static NotificationMessage Decode(BinaryDecoder decoder)
        {
            var message = new NotificationMessage();
            message.SequenceNumber = decoder.ReadUInt32();
            message.PublishTime = decoder.ReadDateTime();
            var count = decoder.ReadInt32();
            for (int i = 0; i < count; i++)
            {
                message.NotificationData.Add(ExtensionObject.Decode(decoder));
            }
            return message;
        }
    }

    public class PublishResult
    {
        public uint SubscriptionId { get; set; }
        public uint[] AvailableSequenceNumbers { get; set; } = Array.Empty<uint>();
        public bool MoreNotifications { get; set; }
        public NotificationMessage NotificationMessage { get; set; } = new NotificationMessage();
        public StatusCode[] Results { get; set; } = Array.Empty<StatusCode>();

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
            var resultsCount = decoder.ReadInt32();
            result.Results = resultsCount > 0 ? new StatusCode[resultsCount] : Array.Empty<StatusCode>();
            for (int i = 0; i < resultsCount; i++)
            {
                result.Results[i] = new StatusCode(decoder.ReadUInt32());
            }
            return result;
        }
    }

    public class PublishResponse : IDecodable<PublishResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();
        public PublishResult Parameters { get; set; } = new PublishResult();

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
