using TinyUa.Core;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using TinyUa.Core.Types;
using TinyUa.Client.Connection;
using TinyUa.Client.Services;

namespace TinyUa.Client.Subscriptions
{

    internal class SubscriptionRouter
    {
        private readonly UaConnection _connection;

        internal ConcurrentDictionary<uint, Subscription> Registry { get; } = new();

        internal SubscriptionRouter(UaConnection connection)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        }

        internal void Register(uint subscriptionId, Subscription subscription)
            => Registry[subscriptionId] = subscription;

        internal void Unregister(uint subscriptionId)
            => Registry.TryRemove(subscriptionId, out _);

        internal bool TryGet(uint subscriptionId, out Subscription? subscription)
            => Registry.TryGetValue(subscriptionId, out subscription);

        internal async Task<CreateSubscriptionResponse> CreateSubscriptionAsync(double publishingInterval = 1000.0,
            uint lifetimeCount = 3600, uint maxKeepAliveCount = 10)
        {
            var request = new CreateSubscriptionRequest
            {
                RequestHeader = new RequestHeader { AuthenticationToken = _connection.AuthenticationToken ?? new NodeId() },
                Parameters = new CreateSubscriptionParameters
                {
                    RequestedPublishingInterval = publishingInterval,
                    RequestedLifetimeCount = lifetimeCount,
                    RequestedMaxKeepAliveCount = maxKeepAliveCount,
                    PublishingEnabled = true
                }
            };
            var response = await _connection.SendRequestAsync<CreateSubscriptionRequest, CreateSubscriptionResponse>(request).ConfigureAwait(false);
            response.ResponseHeader.ServiceResult.Check();
            return response;
        }

        internal async Task<MonitoredItemCreateResult[]?> CreateMonitoredItemsAsync(uint subscriptionId, NodeId[] nodeIds,
            AttributeId attributeId = AttributeId.Value, double samplingInterval = 1000.0,
            uint[]? clientHandles = null, uint queueSize = 0)
        {
            var items = new MonitoredItemCreateRequest[nodeIds.Length];
            for (int i = 0; i < nodeIds.Length; i++)
            {
                items[i] = new MonitoredItemCreateRequest
                {
                    ItemToMonitor = new ReadValueId { NodeId = nodeIds[i], AttributeId = attributeId },
                    MonitoringMode = MonitoringMode.Reporting,
                    RequestedParameters = new MonitoringParameters
                    {
                        ClientHandle = clientHandles != null && i < clientHandles.Length ? clientHandles[i] : (uint)(i + 1),
                        SamplingInterval = samplingInterval, QueueSize = queueSize, DiscardOldest = true
                    }
                };
            }
            var request = new CreateMonitoredItemsRequest
            {
                RequestHeader = new RequestHeader { AuthenticationToken = _connection.AuthenticationToken ?? new NodeId() },
                Parameters = new CreateMonitoredItemsParameters
                {
                    SubscriptionId = subscriptionId, TimestampsToReturn = TimestampsToReturn.Both, ItemsToCreate = items
                }
            };
            var response = await _connection.SendRequestAsync<CreateMonitoredItemsRequest, CreateMonitoredItemsResponse>(request).ConfigureAwait(false);
            response.ResponseHeader.ServiceResult.Check();
            return response.Results;
        }

        internal async Task<StatusCode[]> DeleteMonitoredItemsAsync(uint subscriptionId, uint[] monitoredItemIds)
        {
            var request = new DeleteMonitoredItemsRequest
            {
                RequestHeader = new RequestHeader { AuthenticationToken = _connection.AuthenticationToken ?? new NodeId() },
                Parameters = new DeleteMonitoredItemsParameters { SubscriptionId = subscriptionId, MonitoredItemIds = monitoredItemIds }
            };

            var response = await _connection.SendRequestAsync<DeleteMonitoredItemsRequest, DeleteMonitoredItemsResponse>(request).ConfigureAwait(false);
            response.ResponseHeader.ServiceResult.Check();
            return response.Results;
        }

        internal async Task<StatusCode[]> DeleteSubscriptionsAsync(uint[] subscriptionIds)
        {
            var request = new DeleteSubscriptionsRequest
            {
                RequestHeader = new RequestHeader { AuthenticationToken = _connection.AuthenticationToken ?? new NodeId() },
                Parameters = new DeleteSubscriptionsParameters { SubscriptionIds = subscriptionIds }
            };
            var response = await _connection.SendRequestAsync<DeleteSubscriptionsRequest, DeleteSubscriptionsResponse>(request).ConfigureAwait(false);
            response.ResponseHeader.ServiceResult.Check();
            return response.Results;
        }

        internal async Task<PublishResponse> PublishAsync(uint subscriptionId, uint sequenceNumber = 0)
        {
            var request = CreatePublishRequest(subscriptionId, sequenceNumber);
            return await _connection.SendRequestAsync<PublishRequest, PublishResponse>(request).ConfigureAwait(false);
        }

        internal async Task SendPublishNoWaitAsync(uint subscriptionId, uint sequenceNumber = 0)
        {
            var request = CreatePublishRequest(subscriptionId, sequenceNumber);
            await _connection.SendRequestNoWaitAsync(request).ConfigureAwait(false);
        }

        internal async Task SendPublishWithCallbackAsync(uint subscriptionId, uint sequenceNumber, Action<byte[]> callback)
        {
            var request = CreatePublishRequest(subscriptionId, sequenceNumber);
            await _connection.SendRequestNoWaitAsync(request, callback).ConfigureAwait(false);
        }

        private PublishRequest CreatePublishRequest(uint subscriptionId, uint sequenceNumber)
        {
            return new PublishRequest
            {
                RequestHeader = new RequestHeader { AuthenticationToken = _connection.AuthenticationToken ?? new NodeId(), TimeoutHint = 0 },
                Parameters = new PublishParameters
                {
                    SubscriptionAcknowledgements = sequenceNumber > 0
                        ? new[] { new SubscriptionAcknowledgement { SubscriptionId = subscriptionId, SequenceNumber = sequenceNumber } }
                        : Array.Empty<SubscriptionAcknowledgement>()
                }
            };
        }
    }
}
