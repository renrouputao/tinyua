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
        private readonly ConcurrentDictionary<uint, Subscription> _registry = new();

        /// <summary>The session-level publish pump shared by all subscriptions on this connection.</summary>
        internal PublishEngine Engine { get; }

        internal SubscriptionRouter(UaConnection connection, TinyUa.Core.Logging.ILogger? logger = null)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            Engine = new PublishEngine(this, logger ?? TinyUa.Core.Logging.NullLogger.Instance);
        }

        internal void Register(uint subscriptionId, Subscription subscription)
            => _registry[subscriptionId] = subscription;

        internal void Unregister(uint subscriptionId)
            => _registry.TryRemove(subscriptionId, out _);

        internal bool TryGet(uint subscriptionId, out Subscription? subscription)
            => _registry.TryGetValue(subscriptionId, out subscription);

        internal async Task<CreateSubscriptionResponse> CreateSubscriptionAsync(double publishingInterval = 1000.0,
            uint lifetimeCount = 3600, uint maxKeepAliveCount = 10)
        {
            var request = new CreateSubscriptionRequest
            {
                Parameters = new CreateSubscriptionParameters
                {
                    RequestedPublishingInterval = publishingInterval,
                    RequestedLifetimeCount = lifetimeCount,
                    RequestedMaxKeepAliveCount = maxKeepAliveCount,
                    PublishingEnabled = true
                }
            };
            return await _connection.InvokeAsync<CreateSubscriptionRequest, CreateSubscriptionResponse>(request).ConfigureAwait(false);
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
                Parameters = new CreateMonitoredItemsParameters
                {
                    SubscriptionId = subscriptionId, TimestampsToReturn = TimestampsToReturn.Both, ItemsToCreate = items
                }
            };
            var response = await _connection.InvokeAsync<CreateMonitoredItemsRequest, CreateMonitoredItemsResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        internal async Task<StatusCode[]> DeleteMonitoredItemsAsync(uint subscriptionId, uint[] monitoredItemIds)
        {
            var request = new DeleteMonitoredItemsRequest
            {
                Parameters = new DeleteMonitoredItemsParameters { SubscriptionId = subscriptionId, MonitoredItemIds = monitoredItemIds }
            };

            var response = await _connection.InvokeAsync<DeleteMonitoredItemsRequest, DeleteMonitoredItemsResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        internal async Task<StatusCode[]> DeleteSubscriptionsAsync(uint[] subscriptionIds)
        {
            var request = new DeleteSubscriptionsRequest
            {
                Parameters = new DeleteSubscriptionsParameters { SubscriptionIds = subscriptionIds }
            };
            var response = await _connection.InvokeAsync<DeleteSubscriptionsRequest, DeleteSubscriptionsResponse>(request).ConfigureAwait(false);
            return response.Results;
        }

        /// <summary>
        /// Sends one Publish request for the session (fire-and-forget). Per the underlying
        /// SendRequestNoWait contract: a synchronous throw means neither callback fires;
        /// otherwise exactly one of <paramref name="onResponse"/> / <paramref name="onError"/>
        /// eventually fires. <paramref name="responseTimeout"/> bounds the wait so a silently-
        /// dropped Publish response cannot pin an in-flight slot forever.
        /// </summary>
        internal Task SendPublishAsync(SubscriptionAcknowledgement[] acknowledgements,
            Func<byte[], Task> onResponse, Action<Exception> onError, TimeSpan? responseTimeout = null)
        {
            var request = new PublishRequest
            {
                // TimeoutHint 0: Publish is a long poll — the server holds it until data is due.
                RequestHeader = _connection.CreateRequestHeader(timeoutHint: 0),
                Parameters = new PublishParameters { SubscriptionAcknowledgements = acknowledgements }
            };
            return _connection.SendRequestNoWaitAsync(request, onResponse, onError, responseTimeout);
        }
    }
}
