namespace TinyUa.Client.Subscriptions
{
    /// <summary>
    /// Action to take when a subscription's notification dispatch queue is full.
    /// </summary>
    public enum NotificationOverflowPolicy
    {
        /// <summary>
        /// Wait for the callback worker to make room. This applies backpressure to the
        /// session Publish window and preserves every received notification.
        /// </summary>
        Wait,

        /// <summary>
        /// Discard the oldest queued Publish response and retain the most recent one.
        /// </summary>
        DropOldest,

        /// <summary>
        /// Discard the newly received Publish response and retain the existing backlog.
        /// </summary>
        DropNewest
    }

    /// <summary>
    /// Controls how received Publish responses are queued before user notification callbacks run.
    /// A queue is owned by each subscription, so a slow callback on one subscription does not
    /// serialize callback execution for the others.
    /// </summary>
    public sealed class SubscriptionDispatchOptions
    {
        /// <summary>
        /// Maximum number of decoded Publish responses waiting for this subscription's callback
        /// worker. Must be positive. The default of 1024 favors lossless burst absorption while
        /// keeping the backlog bounded.
        /// </summary>
        public int QueueCapacity { get; set; } = 1024;

        /// <summary>
        /// Behavior when <see cref="QueueCapacity"/> is reached. The default, <see cref="NotificationOverflowPolicy.Wait"/>,
        /// preserves notifications and slows the finite Publish window instead of creating an
        /// unbounded backlog.
        /// </summary>
        public NotificationOverflowPolicy OverflowPolicy { get; set; } = NotificationOverflowPolicy.Wait;

        /// <summary>Creates an independent copy of these options.</summary>
        public SubscriptionDispatchOptions Clone() => new()
        {
            QueueCapacity = QueueCapacity,
            OverflowPolicy = OverflowPolicy
        };
    }
}
