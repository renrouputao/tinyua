using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TinyUa.Core.Client.Connection;
using TinyUa.Core.Client.Services;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Transport;

namespace TinyUa.Core.Client.Discovery
{
    public static class EndpointDiscoverer
    {
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
