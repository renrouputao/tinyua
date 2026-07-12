using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Defines the monitoring mode for a monitored item.
    /// </summary>
    public enum MonitoringMode : byte
    {
        /// <summary>Monitoring is disabled.</summary>
        Disabled = 0,
        /// <summary>Sampling only - the item is sampled but changes are not reported.</summary>
        Sampling = 1,
        /// <summary>Reporting - the item is sampled and changes are reported to the client.</summary>
        Reporting = 2
    }

    /// <summary>
    /// Monitoring parameters that define how a monitored item is sampled and reported.
    /// </summary>
    public class MonitoringParameters : IEncodable
    {
        /// <summary>Gets or sets the client-assigned handle used to identify the monitored item in notifications.</summary>
        public uint ClientHandle { get; set; }

        /// <summary>Gets or sets the sampling interval in milliseconds. -1 means use the subscription's publishing interval.</summary>
        public double SamplingInterval { get; set; }

        /// <summary>Gets or sets an optional filter, such as a data change filter, applied to the monitored item.</summary>
        public ExtensionObject? Filter { get; set; }

        /// <summary>Gets or sets the size of the notification queue. Default is 1.</summary>
        public uint QueueSize { get; set; } = 1;

        /// <summary>Gets or sets whether to discard the oldest notifications when the queue is full. Default is true.</summary>
        public bool DiscardOldest { get; set; } = true;

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

    /// <summary>
    /// Represents a request to create a monitored item within a subscription.
    /// </summary>
    public class MonitoredItemCreateRequest : IEncodable
    {
        /// <summary>Gets or sets the read value identifier describing which node to monitor.</summary>
        public ReadValueId ItemToMonitor { get; set; } = new ReadValueId();

        /// <summary>Gets or sets the monitoring mode. Default is Reporting.</summary>
        public MonitoringMode MonitoringMode { get; set; } = MonitoringMode.Reporting;

        /// <summary>Gets or sets the requested monitoring parameters.</summary>
        public MonitoringParameters RequestedParameters { get; set; } = new MonitoringParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            ItemToMonitor.Encode(encoder);
            encoder.WriteUInt32((uint)MonitoringMode);
            RequestedParameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Parameters for the CreateSubscription service request.
    /// </summary>
    public class CreateSubscriptionParameters : IEncodable
    {
        /// <summary>Gets or sets the requested publishing interval in milliseconds. Default is 1000 ms.</summary>
        public double RequestedPublishingInterval { get; set; } = 1000.0;

        /// <summary>Gets or sets the requested lifetime count (number of keep-alive intervals before the subscription expires). Default is 3600.</summary>
        public uint RequestedLifetimeCount { get; set; } = 3600;

        /// <summary>Gets or sets the requested maximum keep-alive count (number of publishing intervals between keep-alive messages). Default is 10.</summary>
        public uint RequestedMaxKeepAliveCount { get; set; } = 10;

        /// <summary>Gets or sets the maximum number of notifications per publish response. 0 means server default.</summary>
        public uint MaxNotificationsPerPublish { get; set; } = 0;

        /// <summary>Gets or sets whether publishing is initially enabled. Default is true.</summary>
        public bool PublishingEnabled { get; set; } = true;

        /// <summary>Gets or sets the relative priority of the subscription. Default is 0 (lowest).</summary>
        public byte Priority { get; set; } = 0;

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

    /// <summary>
    /// Represents the CreateSubscription service request used to create a new subscription on the server.
    /// </summary>
    public class CreateSubscriptionRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the CreateSubscription parameters.</summary>
        public CreateSubscriptionParameters Parameters { get; set; } = new CreateSubscriptionParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(787, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the CreateSubscription service response returned by the server.
    /// </summary>
    public class CreateSubscriptionResponse : IDecodable<CreateSubscriptionResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the newly created subscription identifier.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the revised publishing interval granted by the server, in milliseconds.</summary>
        public double RevisedPublishingInterval { get; set; }

        /// <summary>Gets or sets the revised lifetime count granted by the server.</summary>
        public uint RevisedLifetimeCount { get; set; }

        /// <summary>Gets or sets the revised maximum keep-alive count granted by the server.</summary>
        public uint RevisedMaxKeepAliveCount { get; set; }

        /// <summary>
        /// Decodes a <see cref="CreateSubscriptionResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="CreateSubscriptionResponse"/>.</returns>
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

    /// <summary>
    /// Parameters for the CreateMonitoredItems service request.
    /// </summary>
    public class CreateMonitoredItemsParameters : IEncodable
    {
        /// <summary>Gets or sets the subscription identifier to add monitored items to.</summary>
        public uint SubscriptionId { get; set; }

        /// <summary>Gets or sets the timestamps to return in notifications. Default is Both.</summary>
        public TimestampsToReturn TimestampsToReturn { get; set; } = TimestampsToReturn.Both;

        /// <summary>Gets or sets the array of monitored item creation requests.</summary>
        public MonitoredItemCreateRequest[] ItemsToCreate { get; set; } = Array.Empty<MonitoredItemCreateRequest>();

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

    /// <summary>
    /// Represents the CreateMonitoredItems service request used to add items to a subscription for monitoring.
    /// </summary>
    public class CreateMonitoredItemsRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the CreateMonitoredItems parameters.</summary>
        public CreateMonitoredItemsParameters Parameters { get; set; } = new CreateMonitoredItemsParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(751, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the result of creating a single monitored item.
    /// </summary>
    public class MonitoredItemCreateResult
    {
        /// <summary>Gets or sets the status code for this monitored item creation.</summary>
        public StatusCode StatusCode { get; set; } = new StatusCode();

        /// <summary>Gets or sets the server-assigned identifier for this monitored item.</summary>
        public uint MonitoredItemId { get; set; }

        /// <summary>Gets or sets the revised sampling interval granted by the server, in milliseconds.</summary>
        public double RevisedSamplingInterval { get; set; }

        /// <summary>Gets or sets the revised queue size granted by the server.</summary>
        public uint RevisedQueueSize { get; set; }

        /// <summary>Gets or sets the filter result extension object, if any.</summary>
        public ExtensionObject? FilterResult { get; set; }
    }

    /// <summary>
    /// Represents the CreateMonitoredItems service response returned by the server.
    /// </summary>
    public class CreateMonitoredItemsResponse : IDecodable<CreateMonitoredItemsResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the array of results, one for each monitored item creation request.</summary>
        public MonitoredItemCreateResult[]? Results { get; set; }

        /// <summary>
        /// Decodes a <see cref="CreateMonitoredItemsResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="CreateMonitoredItemsResponse"/>.</returns>
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
