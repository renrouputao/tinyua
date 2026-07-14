using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using TinyUa.Client.Security;
using TinyUa.Client.Services;
using TinyUa.Core;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Security.Certificates;
using TinyUa.Core.Types;
using TinyUa.Transport;

namespace TinyUa.Client.Connection
{
    /// <summary>
    /// Executes the full connect handshake against a server: endpoint discovery and selection,
    /// certificate resolution, security policy setup, Hello, OpenSecureChannel, CreateSession,
    /// and ActivateSession. Owns no lifecycle state — <see cref="UaClient"/> drives it and
    /// reacts to the outcome.
    /// </summary>
    internal sealed class ConnectionOrchestrator
    {
        private readonly UaConnection _connection;
        private readonly UaClientOptions _options;
        private readonly ILogger _logger;

        internal ConnectionOrchestrator(UaConnection connection, UaClientOptions options, ILogger logger)
        {
            _connection = connection;
            _options = options;
            _logger = logger;
        }

        /// <summary>
        /// Runs the handshake. On return the connection has an activated session; on failure the
        /// underlying transport may be in any state and the caller is expected to clean up.
        /// </summary>
        internal async Task ConnectAsync(string endpointUrl)
        {
            var uri = new Uri(endpointUrl);
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : 4840;

            var security = _options.Security;
            var isSecure = SecurityPolicyFactory.IsSecurePolicy(security.Policy);

            X509Certificate2? localCert = null;
            if (isSecure)
            {
                string? certUri;
                (localCert, certUri) = ClientCertificateProvider.LoadOrGenerate(
                    security.Certificate, _options.ApplicationName, _options.ApplicationUri, _logger);

                // Sync ApplicationUri to the loaded certificate's URI SAN — the server rejects an
                // ActivateSession whose ApplicationUri differs from the certificate. The write
                // targets the client's private options snapshot, not the caller's object.
                if (certUri != null && _options.ApplicationUri != certUri)
                {
                    _logger.LogDebug($"Syncing ApplicationUri to cert URI: {certUri}");
                    _options.ApplicationUri = certUri;
                }

                _logger.LogDebug($"Client certificate: {(localCert?.Thumbprint ?? "null")}");
            }

            X509Certificate2? remoteCert = null;
            var resolvedMode = security.Mode;
            string? userTokenPolicyId = null;
            EndpointDescription? selected = null;

            if (isSecure && security.AutoDiscoverServerCertificate)
            {
                _logger.LogDebug("Discovering server endpoints via GetEndpoints (None policy)...");
                var endpoints = await DiscoverEndpointsAsync(host, port, endpointUrl).ConfigureAwait(false);
                SecurityDebugLogger.LogStage("Connect.GetEndpoints",
                    ("endpointCount", endpoints?.Length ?? 0),
                    ("requestedPolicy", security.Policy),
                    ("requestedMode", security.Mode));
                selected = SelectEndpoint(endpoints, security.Policy, security.Mode);
                if (selected == null)
                    throw new UaException(0x80000000,
                        $"No server endpoint matches policy '{security.Policy}' with mode '{security.Mode}'.");

                remoteCert = selected.ServerCertificateObject;
                resolvedMode = selected.SecurityMode;
                SecurityDebugLogger.LogStage("Connect.SelectEndpoint",
                    ("endpointUrl", selected.EndpointUrl),
                    ("securityMode", resolvedMode),
                    ("securityPolicyUri", selected.SecurityPolicyUri),
                    ("serverCertThumbprint", remoteCert?.Thumbprint),
                    ("securityLevel", selected.SecurityLevel));

                // Validate the discovered server certificate unless the caller opted into
                // auto-trust. Without this, AutoAcceptServerCertificate=false had no effect.
                if (!security.AutoAcceptServerCertificate)
                {
                    var validator = new CertificateValidator();
                    try
                    {
                        validator.Validate(remoteCert, isServerCertificate: true);
                    }
                    catch (Exception ex)
                    {
                        throw new UaException(0x80120000,
                            $"Server certificate validation failed: {ex.Message}");
                    }
                }

                // Resolve the server's PolicyId for the configured user token type (UserName or
                // Certificate). Anonymous needs no policy id. Matching by TokenType ensures a
                // Certificate identity gets the certificate policy id, not the username one.
                if (security.UserIdentity.Type != UserTokenType.Anonymous && selected.UserIdentityTokens != null)
                {
                    var tokenPolicy = selected.UserIdentityTokens
                        .FirstOrDefault(t => t.TokenType == security.UserIdentity.Type);
                    userTokenPolicyId = tokenPolicy?.PolicyId;
                }
            }

            _connection.UserTokenPolicyId = userTokenPolicyId;

            var policy = SecurityPolicyFactory.Create(security.Policy, localCert, remoteCert, resolvedMode);
            _connection.SetSecurityPolicy(policy);

            // Use discovered endpoint URL if available, otherwise user-provided
            var effectiveUrl = selected?.EndpointUrl ?? endpointUrl;

            await _connection.ConnectAsync(host, port).ConfigureAwait(false);
            await _connection.SendHelloAsync(effectiveUrl, _options.MaxMessageSize).ConfigureAwait(false);

            var clientNonce = new byte[policy.NonceLength];
            if (clientNonce.Length > 0)
                RandomNumberGenerator.Fill(clientNonce);

            await _connection.OpenSecureChannelAsync(new OpenSecureChannelParameters
            {
                RequestType = SecurityTokenRequestType.Issue,
                SecurityMode = resolvedMode,
                ClientNonce = clientNonce.Length > 0 ? clientNonce : null,
                RequestedLifetime = _options.ChannelLifetime
            }).ConfigureAwait(false);

            var createResponse = await _connection.CreateSessionAsync(effectiveUrl, _options.ApplicationName,
                _options.ApplicationUri, _options.ProductUri, (uint)_options.SessionTimeout).ConfigureAwait(false);

            SecurityDebugLogger.LogStage("Connect.CreateSession",
                ("sessionId", createResponse.SessionId),
                ("serverNonceLen", createResponse.ServerNonce?.Length ?? -1),
                ("serverCertLen", createResponse.ServerCertificate?.Length ?? -1),
                ("serverSignatureAlg", createResponse.ServerSignature?.Algorithm),
                ("endpointsCount", createResponse.ServerEndpoints?.Length ?? 0));

            var identity = UserIdentityFactory.Build(security.UserIdentity, createResponse, policy, userTokenPolicyId);
            await _connection.ActivateSessionAsync(identity).ConfigureAwait(false);
        }

        private async Task<EndpointDescription[]?> DiscoverEndpointsAsync(string host, int port, string endpointUrl)
        {
            await _connection.ConnectAsync(host, port).ConfigureAwait(false);
            try
            {
                await _connection.SendHelloAsync(endpointUrl, _options.MaxMessageSize).ConfigureAwait(false);
                await _connection.OpenSecureChannelAsync(new OpenSecureChannelParameters
                {
                    RequestType = SecurityTokenRequestType.Issue,
                    SecurityMode = MessageSecurityMode.None,
                    ClientNonce = null,
                    RequestedLifetime = 60000
                }).ConfigureAwait(false);

                return await _connection.GetEndpointsAsync(endpointUrl).ConfigureAwait(false);
            }
            finally
            {
                // Politely close the short-lived discovery channel before dropping the socket, so
                // the server doesn't keep it half-open until its own timeout.
                await _connection.CloseSecureChannelAsync().ConfigureAwait(false);
                await _connection.DisconnectAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Picks the best endpoint matching the requested policy: prefer the highest-security-level
        /// endpoint matching policy AND mode, falling back to the best policy-only match.
        /// </summary>
        internal static EndpointDescription? SelectEndpoint(
            EndpointDescription[]? endpoints, string policyName, MessageSecurityMode mode)
        {
            if (endpoints == null || endpoints.Length == 0)
                return null;

            var policyUri = SecurityPolicyFactory.NormalizePolicyUri(policyName);
            var suffix = policyUri.Substring(policyUri.LastIndexOf('#'));

            EndpointDescription? bestExact = null;
            EndpointDescription? bestPolicyOnly = null;
            foreach (var ep in endpoints)
            {
                if (ep.SecurityPolicyUri == null
                    || !ep.SecurityPolicyUri.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (bestPolicyOnly == null || ep.SecurityLevel > bestPolicyOnly.SecurityLevel)
                    bestPolicyOnly = ep;
                if (ep.SecurityMode == mode
                    && (bestExact == null || ep.SecurityLevel > bestExact.SecurityLevel))
                    bestExact = ep;
            }

            return bestExact ?? bestPolicyOnly;
        }
    }
}
