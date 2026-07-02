using System;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Binary;
using TinyUa.Core.Logging;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public class UserTokenPolicy
    {
        public string? PolicyId { get; set; }
        public UserTokenType TokenType { get; set; } = UserTokenType.Anonymous;
        public string? IssuedTokenType { get; set; }
        public string? IssuerEndpointUrl { get; set; }
        public string? SecurityPolicyUri { get; set; }

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

    public class EndpointDescription
    {
        public string? EndpointUrl { get; set; }
        public ApplicationDescription? ServerDescription { get; set; }
        public byte[]? ServerCertificate { get; set; }
        public MessageSecurityMode SecurityMode { get; set; } = MessageSecurityMode.Invalid;
        public string? SecurityPolicyUri { get; set; }
        public UserTokenPolicy[]? UserIdentityTokens { get; set; }
        public string? TransportProfileUri { get; set; }
        public byte SecurityLevel { get; set; }

        public X509Certificate2? ServerCertificateObject
            => ServerCertificate == null ? null : new X509Certificate2(ServerCertificate);

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

    public class GetEndpointsRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public string? EndpointUrl { get; set; }
        public string[]? LocaleIds { get; set; }
        public string[]? ProfileUris { get; set; }

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

    public class GetEndpointsResponse : IDecodable<GetEndpointsResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public EndpointDescription[]? Endpoints { get; set; }

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
