using TinyUa.Core.Binary;
using TinyUa.Core.Types;
using TinyUa.Core.Security;

namespace TinyUa.Core.Client.Services
{
    /// <summary>
    /// Defines the type of OPC UA application.
    /// </summary>
    public enum ApplicationType
    {
        /// <summary>Server application.</summary>
        Server = 0,
        /// <summary>Client application.</summary>
        Client = 1,
        /// <summary>Application that acts as both client and server.</summary>
        ClientAndServer = 2,
        /// <summary>Discovery server application.</summary>
        DiscoveryServer = 3
    }

    /// <summary>
    /// Describes an OPC UA application including its URI, name, type, and discovery URLs.
    /// </summary>
    public class ApplicationDescription : IEncodable
    {
        /// <summary>Gets or sets the globally unique application URI.</summary>
        public string? ApplicationUri { get; set; }

        /// <summary>Gets or sets the product URI.</summary>
        public string? ProductUri { get; set; }

        /// <summary>Gets or sets the localized application name.</summary>
        public LocalizedText? ApplicationName { get; set; }

        /// <summary>Gets or sets the type of application.</summary>
        public ApplicationType ApplicationType { get; set; } = ApplicationType.Client;

        /// <summary>Gets or sets the URI of the gateway server, if applicable.</summary>
        public string? GatewayServerUri { get; set; }

        /// <summary>Gets or sets the discovery profile URI.</summary>
        public string? DiscoveryProfileUri { get; set; }

        /// <summary>Gets or sets the list of discovery URLs where the application can be found.</summary>
        public string[]? DiscoveryUrls { get; set; }

        /// <summary>
        /// Encodes this application description into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

        /// <summary>
        /// Decodes an <see cref="ApplicationDescription"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="ApplicationDescription"/>.</returns>
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

    /// <summary>
    /// Parameters for the CreateSession service request.
    /// </summary>
    public class CreateSessionParameters : IEncodable
    {
        /// <summary>Gets or sets the client application description.</summary>
        public ApplicationDescription ClientDescription { get; set; } = new ApplicationDescription();

        /// <summary>Gets or sets the server URI.</summary>
        public string? ServerUri { get; set; }

        /// <summary>Gets or sets the endpoint URL that the client connected to.</summary>
        public string? EndpointUrl { get; set; }

        /// <summary>Gets or sets a human-readable name for the session.</summary>
        public string? SessionName { get; set; }

        /// <summary>Gets or sets the client-generated nonce for key derivation.</summary>
        public byte[]? ClientNonce { get; set; }

        /// <summary>Gets or sets the DER-encoded client X.509 certificate, or null.</summary>
        public byte[]? ClientCertificate { get; set; }

        /// <summary>Gets or sets the requested session timeout in milliseconds. Default is 1 hour (3600000 ms).</summary>
        public double RequestedSessionTimeout { get; set; } = 3600000;

        /// <summary>Gets or sets the maximum message size the client can receive. 0 means unlimited.</summary>
        public uint MaxResponseMessageSize { get; set; } = 0;

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

    /// <summary>
    /// Represents the CreateSession service request used to create a session with a server.
    /// </summary>
    public class CreateSessionRequest : IEncodable
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the CreateSession parameters.</summary>
        public CreateSessionParameters Parameters { get; set; } = new CreateSessionParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(461, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the CreateSession service response returned by the server.
    /// </summary>
    public class CreateSessionResponse : IDecodable<CreateSessionResponse>
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the newly created session identifier.</summary>
        public NodeId SessionId { get; set; } = new NodeId();

        /// <summary>Gets or sets the authentication token used to authenticate subsequent service calls.</summary>
        public NodeId AuthenticationToken { get; set; } = new NodeId();

        /// <summary>Gets or sets the revised session timeout granted by the server, in milliseconds.</summary>
        public double RevisedSessionTimeout { get; set; }

        /// <summary>Gets or sets the server-generated nonce for key derivation.</summary>
        public byte[]? ServerNonce { get; set; }

        /// <summary>Gets or sets the DER-encoded server X.509 certificate, or null.</summary>
        public byte[]? ServerCertificate { get; set; }

        /// <summary>Gets or sets the list of server endpoints from the server's discovery list.</summary>
        public EndpointDescription[]? ServerEndpoints { get; set; }

        /// <summary>Gets or sets the server signature data used to verify the authenticity of the response.</summary>
        public SignatureData? ServerSignature { get; set; }

        /// <summary>Gets or sets the maximum message size the server allows for requests.</summary>
        public uint MaxRequestMessageSize { get; set; }

        /// <summary>
        /// Gets the server application description from the first endpoint in <see cref="ServerEndpoints"/>, or null if none.
        /// </summary>
        public ApplicationDescription? ServerDescription
            => ServerEndpoints != null && ServerEndpoints.Length > 0 ? ServerEndpoints[0].ServerDescription : null;

        /// <summary>
        /// Decodes a <see cref="CreateSessionResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="CreateSessionResponse"/>.</returns>
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

    /// <summary>
    /// Represents a cryptographic signature with its associated algorithm identifier.
    /// </summary>
    public class SignatureData : IEncodable
    {
        /// <summary>Gets or sets the signature algorithm URI.</summary>
        public string? Algorithm { get; set; }

        /// <summary>Gets or sets the raw signature bytes.</summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Encodes this signature data into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString(Algorithm);
            encoder.WriteByteString(Signature);
        }

        /// <summary>
        /// Decodes a <see cref="SignatureData"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="SignatureData"/>.</returns>
        public static SignatureData Decode(BinaryDecoder decoder)
        {
            return new SignatureData
            {
                Algorithm = decoder.ReadString(),
                Signature = decoder.ReadByteString()
            };
        }
    }

    /// <summary>
    /// Parameters for the ActivateSession service request.
    /// </summary>
    public class ActivateSessionParameters : IEncodable
    {
        /// <summary>Gets or sets the client signature used to verify the client's identity.</summary>
        public SignatureData ClientSignature { get; set; } = new SignatureData();

        /// <summary>Gets or sets the user identity token for authenticating the user.</summary>
        public UserIdentityToken? UserIdentity { get; set; }

        /// <summary>Gets or sets the user token signature for verifying the user identity token.</summary>
        public SignatureData UserTokenSignature { get; set; } = new SignatureData();

        /// <summary>
        /// Encodes these parameters into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            ClientSignature.Encode(encoder);

            // clientSoftwareCertificates — not used, encode as null array
            encoder.WriteInt32(-1);

            // localeIds — Kepware requires this before UserIdentityToken
            encoder.WriteInt32(1);
            encoder.WriteString("en");

            if (UserIdentity == null || UserIdentity.TokenType == UserTokenType.Anonymous)
            {
                NodeIdCodec.Encode(encoder, new NodeId(321, 0));
                encoder.WriteByte(1);
                var bodyEncoder = new BinaryEncoder();
                bodyEncoder.WriteString(UserIdentity?.PolicyId);
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

    /// <summary>
    /// Represents the ActivateSession service request used to activate an existing session with user credentials.
    /// </summary>
    public class ActivateSessionRequest : IEncodable
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the ActivateSession parameters.</summary>
        public ActivateSessionParameters Parameters { get; set; } = new ActivateSessionParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(467, 0));
            RequestHeader.Encode(encoder);
            Parameters.Encode(encoder);
        }
    }

    /// <summary>
    /// Represents the ActivateSession service response returned by the server.
    /// </summary>
    public class ActivateSessionResponse : IDecodable<ActivateSessionResponse>
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the server-generated nonce for subsequent key derivation.</summary>
        public byte[]? ServerNonce { get; set; }

        /// <summary>
        /// Decodes an <see cref="ActivateSessionResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="ActivateSessionResponse"/>.</returns>
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

    /// <summary>
    /// Represents the CloseSession service request used to close an active session.
    /// </summary>
    public class CloseSessionRequest : IEncodable
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets whether to also delete all subscriptions associated with the session. Default is true.</summary>
        public bool DeleteSubscriptions { get; set; } = true;

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(473, 0));
            RequestHeader.Encode(encoder);
            encoder.WriteBoolean(DeleteSubscriptions);
        }
    }

    /// <summary>
    /// Represents the CloseSession service response returned by the server.
    /// </summary>
    public class CloseSessionResponse : IDecodable<CloseSessionResponse>
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = new ResponseHeader();

        /// <summary>
        /// Decodes a <see cref="CloseSessionResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="CloseSessionResponse"/>.</returns>
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
