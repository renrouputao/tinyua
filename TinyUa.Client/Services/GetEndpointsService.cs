using TinyUa.Core;
using System;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Describes a user token policy supported by an endpoint.
    /// </summary>
    public class UserTokenPolicy
    {
        /// <summary>Gets or sets the policy identifier.</summary>
        public string? PolicyId { get; set; }

        /// <summary>Gets or sets the type of user identity token required.</summary>
        public UserTokenType TokenType { get; set; } = UserTokenType.Anonymous;

        /// <summary>Gets or sets the type of issued token (applicable when <see cref="TokenType"/> is IssuedToken).</summary>
        public string? IssuedTokenType { get; set; }

        /// <summary>Gets or sets the URL of the issuer endpoint.</summary>
        public string? IssuerEndpointUrl { get; set; }

        /// <summary>Gets or sets the security policy URI for the token.</summary>
        public string? SecurityPolicyUri { get; set; }

        /// <summary>
        /// Decodes a <see cref="UserTokenPolicy"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="UserTokenPolicy"/>.</returns>
        public static UserTokenPolicy Decode(BinaryDecoder decoder)
        {
            return new UserTokenPolicy
            {
                PolicyId = decoder.ReadString(),
                TokenType = (UserTokenType)decoder.ReadInt32(),
                IssuedTokenType = decoder.ReadString(),
                IssuerEndpointUrl = decoder.ReadString(),
                SecurityPolicyUri = decoder.ReadString()
            };
        }
    }

    /// <summary>
    /// Describes an OPC UA server endpoint including its URL, security configuration, and supported user token policies.
    /// </summary>
    public class EndpointDescription
    {
        /// <summary>Gets or sets the endpoint URL.</summary>
        public string? EndpointUrl { get; set; }

        /// <summary>Gets or sets the server application description.</summary>
        public ApplicationDescription? ServerDescription { get; set; }

        /// <summary>Gets or sets the DER-encoded X.509 certificate for the server, or null.</summary>
        public byte[]? ServerCertificate { get; set; }

        /// <summary>Gets or sets the message security mode required by this endpoint.</summary>
        public MessageSecurityMode SecurityMode { get; set; } = MessageSecurityMode.Invalid;

        /// <summary>Gets or sets the security policy URI for this endpoint.</summary>
        public string? SecurityPolicyUri { get; set; }

        /// <summary>Gets or sets the user identity token policies supported by this endpoint.</summary>
        public UserTokenPolicy[]? UserIdentityTokens { get; set; }

        /// <summary>Gets or sets the transport profile URI (e.g., for UA-Tcp).</summary>
        public string? TransportProfileUri { get; set; }

        /// <summary>Gets or sets the security level assigned to this endpoint. Higher values indicate stronger security.</summary>
        public byte SecurityLevel { get; set; }

        /// <summary>
        /// Gets the server certificate as an <see cref="X509Certificate2"/> object, or null if no certificate is present.
        /// </summary>
        public X509Certificate2? ServerCertificateObject
            => ServerCertificate == null ? null : new X509Certificate2(ServerCertificate);

        /// <summary>
        /// Decodes an <see cref="EndpointDescription"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="EndpointDescription"/>.</returns>
        public static EndpointDescription Decode(BinaryDecoder decoder)
        {
            var ep = new EndpointDescription
            {
                EndpointUrl = decoder.ReadString(),
                ServerDescription = ApplicationDescription.Decode(decoder),
                ServerCertificate = decoder.ReadByteString(),
                SecurityMode = (MessageSecurityMode)decoder.ReadInt32(),
                SecurityPolicyUri = decoder.ReadString()
            };

            var tokenCount = decoder.ReadInt32();
            if (tokenCount > 0)
            {
                ep.UserIdentityTokens = new UserTokenPolicy[tokenCount];
                for (int i = 0; i < tokenCount; i++)
                    ep.UserIdentityTokens[i] = UserTokenPolicy.Decode(decoder);
            }

            ep.TransportProfileUri = decoder.ReadString();
            ep.SecurityLevel = decoder.ReadByte();
            return ep;
        }
    }

    /// <summary>
    /// Represents the GetEndpoints service request used to discover available server endpoints.
    /// </summary>
    public class GetEndpointsRequest : IEncodable
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the endpoint URL to query, or null to return all endpoints.</summary>
        public string? EndpointUrl { get; set; }

        /// <summary>Gets or sets the list of locale identifiers for localized text in the response.</summary>
        public string[]? LocaleIds { get; set; }

        /// <summary>Gets or sets the list of transport profile URIs to filter by.</summary>
        public string[]? ProfileUris { get; set; }

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(428, 0));
            RequestHeader.Encode(encoder);
            encoder.WriteString(EndpointUrl);

            if (LocaleIds == null)
                encoder.WriteInt32(-1);
            else
            {
                encoder.WriteInt32(LocaleIds.Length);
                foreach (var loc in LocaleIds)
                    encoder.WriteString(loc);
            }

            if (ProfileUris == null)
                encoder.WriteInt32(-1);
            else
            {
                encoder.WriteInt32(ProfileUris.Length);
                foreach (var uri in ProfileUris)
                    encoder.WriteString(uri);
            }
        }
    }

    /// <summary>
    /// Represents the GetEndpoints service response returned by the server.
    /// </summary>
    public class GetEndpointsResponse : IDecodable<GetEndpointsResponse>
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the list of endpoint descriptions returned by the server.</summary>
        public EndpointDescription[]? Endpoints { get; set; }

        /// <summary>
        /// Decodes a <see cref="GetEndpointsResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="GetEndpointsResponse"/>.</returns>
        public static GetEndpointsResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            SecurityDebugLogger.LogStage("GetEndpointsResponse.Decode",
                ("totalLen", decoder.Length));

            var response = new GetEndpointsResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };

            SecurityDebugLogger.LogStage("GetEndpointsResponse.Decode",
                ("afterResponseHeader", decoder.Position),
                ("remaining", decoder.Remaining));

            var count = decoder.ReadInt32();
            SecurityDebugLogger.LogStage("GetEndpointsResponse.Decode",
                ("endpointCount", count),
                ("afterCount", decoder.Position));

            if (count > 0)
            {
                response.Endpoints = new EndpointDescription[count];
                for (int i = 0; i < count; i++)
                {
                    response.Endpoints[i] = EndpointDescription.Decode(decoder);
                    SecurityDebugLogger.LogStage("GetEndpointsResponse.Decode",
                        ("endpointIdx", i),
                        ("afterEndpoint", decoder.Position),
                        ("remaining", decoder.Remaining),
                        ("epUrl", response.Endpoints[i].EndpointUrl),
                        ("epSecPolicy", response.Endpoints[i].SecurityPolicyUri),
                        ("epCertLen", response.Endpoints[i].ServerCertificate?.Length ?? -1),
                        ("epTokenCount", response.Endpoints[i].UserIdentityTokens?.Length ?? -1));
                }
            }

            SecurityDebugLogger.LogStage("GetEndpointsResponse.Decode",
                ("beforeSkipDiag", decoder.Position),
                ("remaining", decoder.Remaining));
            decoder.SkipDiagnosticInfos();
            return response;
        }
    }
}
