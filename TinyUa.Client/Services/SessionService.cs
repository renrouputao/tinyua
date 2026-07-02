using TinyUa.Core.Binary;
using TinyUa.Core.Types;
using TinyUa.Core.Security;

namespace TinyUa.Core.Client.Services
{
    public enum ApplicationType
    {
        Server = 0,
        Client = 1,
        ClientAndServer = 2,
        DiscoveryServer = 3
    }

    public class ApplicationDescription : IEncodable
    {
        public string? ApplicationUri { get; set; }
        public string? ProductUri { get; set; }
        public LocalizedText? ApplicationName { get; set; }
        public ApplicationType ApplicationType { get; set; } = ApplicationType.Client;
        public string? GatewayServerUri { get; set; }
        public string? DiscoveryProfileUri { get; set; }
        public string[]? DiscoveryUrls { get; set; }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString(ApplicationUri);
            encoder.WriteString(ProductUri);
            LocalizedTextCodec.Encode(encoder, ApplicationName);
            encoder.WriteInt32((int)ApplicationType);
            encoder.WriteString(GatewayServerUri);
            encoder.WriteString(DiscoveryProfileUri);

            if (DiscoveryUrls == null)
            {
                encoder.WriteInt32(-1);
            }
            else
            {
                encoder.WriteInt32(DiscoveryUrls.Length);
                foreach (var url in DiscoveryUrls)
                {
                    encoder.WriteString(url);
                }
            }
        }

        public static ApplicationDescription Decode(BinaryDecoder decoder)
        {
            var desc = new ApplicationDescription
            {
                ApplicationUri = decoder.ReadString(),
                ProductUri = decoder.ReadString(),
                ApplicationName = LocalizedTextCodec.Decode(decoder),
                ApplicationType = (ApplicationType)decoder.ReadInt32(),
                GatewayServerUri = decoder.ReadString(),
                DiscoveryProfileUri = decoder.ReadString()
            };

            var urlCount = decoder.ReadInt32();
            if (urlCount > 0)
            {
                desc.DiscoveryUrls = new string[urlCount];
                for (int i = 0; i < urlCount; i++)
                    desc.DiscoveryUrls[i] = decoder.ReadString()!;
            }

            return desc;
        }
    }

    public class CreateSessionParameters : IEncodable
    {
        public ApplicationDescription ClientDescription { get; set; } = new ApplicationDescription();
        public string? ServerUri { get; set; }
        public string? EndpointUrl { get; set; }
        public string? SessionName { get; set; }
        public byte[]? ClientNonce { get; set; }
        public byte[]? ClientCertificate { get; set; }
        public double RequestedSessionTimeout { get; set; } = 3600000;
        public uint MaxResponseMessageSize { get; set; } = 0;

        public void Encode(BinaryEncoder encoder)
        {
            ClientDescription.Encode(encoder);
            encoder.WriteString(ServerUri);
            encoder.WriteString(EndpointUrl);
            encoder.WriteString(SessionName);
            encoder.WriteByteString(ClientNonce);
            encoder.WriteByteString(ClientCertificate);
            encoder.WriteDouble(RequestedSessionTimeout);
            encoder.WriteUInt32(MaxResponseMessageSize);
        }
    }

    public class CreateSessionRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public CreateSessionParameters Parameters { get; set; } = new CreateSessionParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(461, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class CreateSessionResponse : IDecodable<CreateSessionResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public NodeId SessionId { get; set; } = new NodeId();
        public NodeId AuthenticationToken { get; set; } = new NodeId();
        public double RevisedSessionTimeout { get; set; }
        public byte[]? ServerNonce { get; set; }
        public byte[]? ServerCertificate { get; set; }
        public EndpointDescription[]? ServerEndpoints { get; set; }
        public SignatureData? ServerSignature { get; set; }
        public uint MaxRequestMessageSize { get; set; }

        public ApplicationDescription? ServerDescription
            => ServerEndpoints != null && ServerEndpoints.Length > 0 ? ServerEndpoints[0].ServerDescription : null;

        public static CreateSessionResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new CreateSessionResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                SessionId = NodeIdCodec.Decode(decoder),
                AuthenticationToken = NodeIdCodec.Decode(decoder),
                RevisedSessionTimeout = decoder.ReadDouble(),
                ServerNonce = decoder.ReadByteString(),
                ServerCertificate = decoder.ReadByteString()
            };

            var endpointCount = decoder.ReadInt32();
            if (endpointCount > 0)
            {
                response.ServerEndpoints = new EndpointDescription[endpointCount];
                for (int i = 0; i < endpointCount; i++)
                    response.ServerEndpoints[i] = EndpointDescription.Decode(decoder);
            }

            var certCount = decoder.ReadInt32();
            for (int i = 0; i < certCount; i++)
            {
                decoder.ReadByteString();
                decoder.ReadByteString();
            }

            response.ServerSignature = SignatureData.Decode(decoder);
            response.MaxRequestMessageSize = decoder.ReadUInt32();

            return response;
        }
    }

    public class SignatureData : IEncodable
    {
        public string? Algorithm { get; set; }
        public byte[]? Signature { get; set; }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString(Algorithm);
            encoder.WriteByteString(Signature);
        }

        public static SignatureData Decode(BinaryDecoder decoder)
        {
            return new SignatureData
            {
                Algorithm = decoder.ReadString(),
                Signature = decoder.ReadByteString()
            };
        }
    }

    public class ActivateSessionParameters : IEncodable
    {
        public SignatureData ClientSignature { get; set; } = new SignatureData();
        public UserIdentityToken? UserIdentity { get; set; }

        public SignatureData UserTokenSignature { get; set; } = new SignatureData();

        public void Encode(BinaryEncoder encoder)
        {
            ClientSignature.Encode(encoder);

            encoder.WriteInt32(-1);

            encoder.WriteInt32(1);
            encoder.WriteString("en");

            if (UserIdentity == null || UserIdentity.TokenType == UserTokenType.Anonymous)
            {
                NodeIdCodec.Encode(encoder, new NodeId(321, 0));
                encoder.WriteByte(1);
                var bodyEncoder = new BinaryEncoder();
                bodyEncoder.WriteString("open");
                encoder.WriteByteString(bodyEncoder.ToByteArray());
            }
            else if (UserIdentity.TokenType == UserTokenType.UserName)
            {
                NodeIdCodec.Encode(encoder, new NodeId(324, 0));
                encoder.WriteByte(1);
                var bodyEncoder = new BinaryEncoder();
                bodyEncoder.WriteString(UserIdentity.PolicyId ?? "open");
                bodyEncoder.WriteString(UserIdentity.Username);
                bodyEncoder.WriteByteString(UserIdentity.Password);
                bodyEncoder.WriteString(UserIdentity.EncryptionAlgorithm);
                encoder.WriteByteString(bodyEncoder.ToByteArray());
            }
            else if (UserIdentity.TokenType == UserTokenType.Certificate)
            {
                NodeIdCodec.Encode(encoder, new NodeId(327, 0));
                encoder.WriteByte(1);
                var bodyEncoder = new BinaryEncoder();
                bodyEncoder.WriteString(UserIdentity.PolicyId ?? "open");
                bodyEncoder.WriteByteString(UserIdentity.IssuedId);
                encoder.WriteByteString(bodyEncoder.ToByteArray());
            }

            UserTokenSignature.Encode(encoder);
        }
    }

    public class ActivateSessionRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public ActivateSessionParameters Parameters { get; set; } = new ActivateSessionParameters();

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(467, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    public class ActivateSessionResponse : IDecodable<ActivateSessionResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public byte[]? ServerNonce { get; set; }

        public static ActivateSessionResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();

            var response = new ActivateSessionResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                ServerNonce = decoder.ReadByteString()
            };

            return response;
        }
    }

    public class CloseSessionRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public bool DeleteSubscriptions { get; set; } = true;

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(473, 0));
            RequestHeader.Encode(encoder);
            encoder.WriteBoolean(DeleteSubscriptions);
        }
    }

    public class CloseSessionResponse : IDecodable<CloseSessionResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        public static CloseSessionResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();
            return new CloseSessionResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder)
            };
        }
    }
}
