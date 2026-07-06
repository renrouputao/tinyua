using TinyUa.Core;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Client.Connection;
using TinyUa.Client.Services;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Transport;

namespace TinyUa.Client.Discovery
{
    /// <summary>
    /// Provides a fast, connection-oriented mechanism to discover available OPC UA endpoints
    /// from a server by opening a short-lived connection and calling the GetEndpoints service.
    /// </summary>
    public static class EndpointDiscoverer
    {
        /// <summary>
        /// Connects to the specified OPC UA server, retrieves its endpoints, and returns
        /// a deduplicated, relevance-sorted list of <see cref="DiscoveredEndpoint"/> instances.
        /// Secure endpoints are sorted before non-secure ones; within each group endpoints
        /// are ordered by descending security level.
        /// </summary>
        /// <param name="endpointUrl">The discovery URL of the server (e.g. "opc.tcp://host:4840").</param>
        /// <param name="timeoutMs">Connection and request timeout in milliseconds. Defaults to 10000.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A deduplicated, sorted list of discovered endpoints.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="endpointUrl"/> is null or whitespace.</exception>
        public static async Task<IReadOnlyList<DiscoveredEndpoint>> DiscoverAsync(
            string endpointUrl, int timeoutMs = 10000, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(endpointUrl))
                throw new ArgumentException("Endpoint URL must not be empty.", nameof(endpointUrl));
            cancellationToken.ThrowIfCancellationRequested();

            var uri = new Uri(endpointUrl);
            var host = uri.Host;
            var port = uri.Port <= 0 ? 4840 : uri.Port;

            EndpointDescription[]? endpoints;
            using (var conn = new UaConnection(timeoutMs, NullLogger.Instance))
            {
                await conn.ConnectAsync(host, port).ConfigureAwait(false);
                try
                {
                    await conn.SendHelloAsync(endpointUrl, 0).ConfigureAwait(false);
                    await conn.OpenSecureChannelAsync(new OpenSecureChannelParameters
                    {
                        RequestType = SecurityTokenRequestType.Issue,
                        SecurityMode = MessageSecurityMode.None,
                        ClientNonce = null,
                        RequestedLifetime = 60000
                    }).ConfigureAwait(false);

                    endpoints = await conn.GetEndpointsAsync(endpointUrl).ConfigureAwait(false);
                }
                finally
                {
                    try { await conn.DisconnectAsync().ConfigureAwait(false); }
                    catch { }
                }
            }

            if (endpoints == null || endpoints.Length == 0)
                return Array.Empty<DiscoveredEndpoint>();

            var projected = endpoints
                .Select(Project)
                .GroupBy(e => (e.SecurityPolicy, e.SecurityMode, e.SecurityLevel))
                .Select(g => g.First())
                .ToList();

            projected.Sort((a, b) =>
            {
                if (a.IsSecure != b.IsSecure) return a.IsSecure ? -1 : 1;
                return b.SecurityLevel.CompareTo(a.SecurityLevel);
            });

            return projected;
        }

        private static DiscoveredEndpoint Project(EndpointDescription ep)
        {
            var uri = ep.SecurityPolicyUri ?? "";
            var shortName = uri;
            var hashIdx = uri.LastIndexOf('#');
            if (hashIdx >= 0 && hashIdx + 1 < uri.Length)
                shortName = uri.Substring(hashIdx + 1);
            if (string.IsNullOrEmpty(shortName))
                shortName = "None";

            var tokenTypes = (ep.UserIdentityTokens ?? Array.Empty<UserTokenPolicy>())
                .Select(t => t.TokenType)
                .Distinct()
                .ToList();

            return new DiscoveredEndpoint
            {
                EndpointUrl = ep.EndpointUrl ?? "",
                SecurityPolicy = shortName,
                SecurityPolicyUri = uri,
                SecurityMode = ep.SecurityMode,
                SecurityLevel = ep.SecurityLevel,
                UserTokenTypes = tokenTypes
            };
        }
    }
}
