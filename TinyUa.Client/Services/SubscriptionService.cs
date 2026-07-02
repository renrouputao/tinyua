using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public enum MonitoringMode : byte
    {
        Disabled = 0,
        Sampling = 1,
        Reporting = 2
    }

    public class MonitoringParameters : IEncodable
    {
        public uint ClientHandle { get; set; }
        public double SamplingInterval { get; set; }
        public ExtensionObject? Filter { get; set; }
        public uint QueueSize { get; set; } = 1;
        public bool DiscardOldest { get; set; } = true;

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(ClientHandle);
            encoder.WriteDouble(SamplingInterval);
            encoder.WriteByte(2);
            encoder.WriteUInt16(0);
            encoder.WriteUInt32(0);
            encoder.WriteByte(0);
            encoder.WriteUInt32(QueueSize);
            encoder.WriteBoolean(DiscardOldest);
        }
    }

    public class MonitoredItemCreateRequest : IEncodable
    {
        public ReadValueId ItemToMonitor { get; set; } = new ReadValueId();
        public MonitoringMode MonitoringMode { get; set; } = MonitoringMode.Reporting;
        public MonitoringParameters RequestedParameters { get; set; } = new MonitoringParameters();

        public void Encode(BinaryEncoder encoder)
        {
            ItemToMonitor.Encode(encoder);
            encoder.WriteUInt32((uint)MonitoringMode);
            RequestedParameters.Encode(encoder);
        }
    }

    public class CreateSubscriptionParameters : IEncodable
    {
        public double RequestedPublishingInterval { get; set; } = 1000.0;
        public uint RequestedLifetimeCount { get; set; } = 3600;
        public uint RequestedMaxKeepAliveCount { get; set; } = 10;
        public uint MaxNotificationsPerPublish { get; set; } = 0;
        public bool PublishingEnabled { get; set; } = true;
        public byte Priority { get; set; } = 0;

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteDouble(RequestedPublishingInterval);
            encoder.WriteUInt32(RequestedLifetimeCount);
            encoder.WriteUInt32(RequestedMaxKeepAliveCount);
            encoder.WriteUInt32(MaxNotificationsPerPublish);
            encoder.WriteBoolean(PublishingEnabled);
            encoder.WriteByte(Priority);
        }
    }

    public class CreateSubscriptionRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public CreateSubscriptionParameters Parameters { get; set; } = new CreateSubscriptionParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(787, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class CreateSubscriptionResponse : IDecodable<CreateSubscriptionResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public uint SubscriptionId { get; set; }
        public double RevisedPublishingInterval { get; set; }
        public uint RevisedLifetimeCount { get; set; }
        public uint RevisedMaxKeepAliveCount { get; set; }

        public static CreateSubscriptionResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            return new CreateSubscriptionResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                SubscriptionId = decoder.ReadUInt32(),
                RevisedPublishingInterval = decoder.ReadDouble(),
                RevisedLifetimeCount = decoder.ReadUInt32(),
                RevisedMaxKeepAliveCount = decoder.ReadUInt32()
            };
        }
    }

    public class CreateMonitoredItemsParameters : IEncodable
    {
        public uint SubscriptionId { get; set; }
        public TimestampsToReturn TimestampsToReturn { get; set; } = TimestampsToReturn.Both;
        public MonitoredItemCreateRequest[] ItemsToCreate { get; set; } = Array.Empty<MonitoredItemCreateRequest>();

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SubscriptionId);
            encoder.WriteInt32((int)TimestampsToReturn);
            encoder.WriteInt32(ItemsToCreate.Length);
            foreach (var item in ItemsToCreate)
            {
                item.Encode(encoder);
            }
        }
    }

    public class CreateMonitoredItemsRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public CreateMonitoredItemsParameters Parameters { get; set; } = new CreateMonitoredItemsParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(751, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class MonitoredItemCreateResult
    {
        public StatusCode StatusCode { get; set; } = new StatusCode();
        public uint MonitoredItemId { get; set; }
        public double RevisedSamplingInterval { get; set; }
        public uint RevisedQueueSize { get; set; }
        public ExtensionObject? FilterResult { get; set; }
    }

    public class CreateMonitoredItemsResponse : IDecodable<CreateMonitoredItemsResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public MonitoredItemCreateResult[]? Results { get; set; }

        public static CreateMonitoredItemsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new CreateMonitoredItemsResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            var count = decoder.ReadInt32();
            if (count > 0)
            {
                response.Results = new MonitoredItemCreateResult[count];
                for (int i = 0; i < count; i++)
                {
                    response.Results[i] = new MonitoredItemCreateResult
                    {
                        StatusCode = new StatusCode(decoder.ReadUInt32()),
                        MonitoredItemId = decoder.ReadUInt32(),
                        RevisedSamplingInterval = decoder.ReadDouble(),
                        RevisedQueueSize = decoder.ReadUInt32()
                    };

                    response.Results[i].FilterResult = ExtensionObject.Decode(decoder);
                }
            }

            decoder.SkipDiagnosticInfos();

            return response;
        }
    }
}
