using TinyUa.Core;
using System;
using TinyUa.Core.Binary;
using TinyUa.Transport;
using TinyUa.Core.Types;

namespace TinyUa.Client.Services
{
    /// <summary>
    /// Represents the OPC UA service request header that is included in every service request.
    /// </summary>
    public class RequestHeader : IEncodable
    {
        /// <summary>Gets or sets the authentication token (session authentication token node id).</summary>
        public NodeId AuthenticationToken { get; set; } = new NodeId();

        /// <summary>Gets or sets the timestamp of the request.</summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>Gets or sets the client-assigned request handle used to correlate responses.</summary>
        public uint RequestHandle { get; set; }

        /// <summary>Gets or sets the diagnostics flags indicating what diagnostic information to return.</summary>
        public uint ReturnDiagnostics { get; set; }

        /// <summary>Gets or sets the audit entry identifier for auditing purposes.</summary>
        public string? AuditEntryId { get; set; }

        /// <summary>Gets or sets the timeout hint in milliseconds. 0 means no timeout hint.</summary>
        public uint TimeoutHint { get; set; } = 0;

        /// <summary>Gets or sets an optional additional header as an extension object.</summary>
        public ExtensionObject? AdditionalHeader { get; set; }

        /// <summary>
        /// Encodes this request header into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, AuthenticationToken);
            encoder.WriteDateTime(Timestamp);
            encoder.WriteUInt32(RequestHandle);
            encoder.WriteUInt32(ReturnDiagnostics);
            encoder.WriteString(AuditEntryId);
            encoder.WriteUInt32(TimeoutHint);
            if (AdditionalHeader != null)
            {
                AdditionalHeader.Encode(encoder);
            }
            else
            {
                NodeIdCodec.Encode(encoder, new NodeId(0, 0));
                encoder.WriteByte(0);
            }
        }
    }

    /// <summary>
    /// Represents the OPC UA service response header that is included in every service response.
    /// </summary>
    public class ResponseHeader : IDecodable<ResponseHeader>
    {
        /// <summary>Gets or sets the timestamp of the response.</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Gets or sets the request handle echoed from the corresponding request.</summary>
        public uint RequestHandle { get; set; }

        /// <summary>Gets or sets the overall service result status code.</summary>
        public StatusCode ServiceResult { get; set; } = new StatusCode();

        /// <summary>Gets or sets optional diagnostic information associated with the service result.</summary>
        public DiagnosticInfo? ServiceDiagnostics { get; set; }

        /// <summary>Gets or sets a string table used for compact encoding of diagnostic strings.</summary>
        public string[]? StringTable { get; set; }

        /// <summary>Gets or sets an optional additional header as an extension object.</summary>
        public ExtensionObject? AdditionalHeader { get; set; }

        /// <summary>
        /// Decodes a <see cref="ResponseHeader"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="ResponseHeader"/>.</returns>
        public static ResponseHeader Decode(BinaryDecoder decoder)
        {
            var header = new ResponseHeader
            {
                Timestamp = decoder.ReadDateTime(),
                RequestHandle = decoder.ReadUInt32(),
                ServiceResult = new StatusCode(decoder.ReadUInt32())
            };

            header.ServiceDiagnostics = DiagnosticInfo.Decode(decoder);
            var stringCount = decoder.ReadArrayLength();
            if (stringCount >= 0)
            {
                header.StringTable = new string[stringCount];
                for (int i = 0; i < stringCount; i++)
                    header.StringTable[i] = decoder.ReadString() ?? "";
            }

            var typeId = NodeIdCodec.Decode(decoder);
            var encoding = decoder.ReadByte();
            if (encoding == 1)
            {

                var bodyLen = decoder.ReadInt32();
                if (bodyLen > 0)
                {
                    decoder.ReadBytes(bodyLen);
                }
            }
            else if (encoding == 2)
            {

                decoder.ReadString();
            }

            return header;
        }
    }

    /// <summary>
    /// Represents OPC UA diagnostic information associated with a service result.
    /// </summary>
    public class DiagnosticInfo
    {
        public int SymbolicId { get; set; } = -1;
        public int NamespaceUri { get; set; } = -1;
        public int Locale { get; set; } = -1;
        public int LocalizedText { get; set; } = -1;
        public string? AdditionalInfo { get; set; }
        public StatusCode? InnerStatusCode { get; set; }
        public DiagnosticInfo? InnerDiagnosticInfo { get; set; }

        internal static DiagnosticInfo? Decode(BinaryDecoder decoder, int depth = 0)
        {
            if (depth >= 64) throw new InvalidOperationException("DiagnosticInfo nesting exceeds 64 levels.");
            var mask = decoder.ReadByte();
            if (mask == 0) return null;
            if ((mask & 0x80) != 0) throw new InvalidOperationException("Invalid DiagnosticInfo encoding mask.");
            var result = new DiagnosticInfo();
            if ((mask & 0x01) != 0) result.SymbolicId = decoder.ReadInt32();
            if ((mask & 0x02) != 0) result.NamespaceUri = decoder.ReadInt32();
            if ((mask & 0x04) != 0) result.Locale = decoder.ReadInt32();
            if ((mask & 0x08) != 0) result.LocalizedText = decoder.ReadInt32();
            if ((mask & 0x10) != 0) result.AdditionalInfo = decoder.ReadString();
            if ((mask & 0x20) != 0) result.InnerStatusCode = new StatusCode(decoder.ReadUInt32());
            if ((mask & 0x40) != 0) result.InnerDiagnosticInfo = Decode(decoder, depth + 1);
            return result;
        }
    }

    /// <summary>
    /// Represents the OpenSecureChannel service request used to establish or renew a secure channel.
    /// </summary>
    public class OpenSecureChannelRequest : IServiceRequest
    {
        /// <summary>Gets or sets the service request header.</summary>
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();

        /// <summary>Gets or sets the OpenSecureChannel parameters.</summary>
        public OpenSecureChannelParameters Parameters { get; set; } = new OpenSecureChannelParameters();

        /// <summary>
        /// Encodes this request into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, new NodeId(446, 0));
            RequestHeader.Encode(encoder);
            encoder.WriteUInt32(0);
            encoder.WriteUInt32((uint)Parameters.RequestType);
            encoder.WriteUInt32((uint)Parameters.SecurityMode);
            encoder.WriteByteString(Parameters.ClientNonce);
            encoder.WriteUInt32(Parameters.RequestedLifetime);
        }

        /// <summary>
        /// Prints debug information about this request to the console.
        /// </summary>
        public void DebugPrint()
        {
            Console.WriteLine("[DEBUG] OpenSecureChannelRequest:");
            Console.WriteLine($"  TypeId: i=446");
            Console.WriteLine($"  RequestHeader.AuthenticationToken: {RequestHeader.AuthenticationToken}");
            Console.WriteLine($"  RequestHeader.Timestamp: {RequestHeader.Timestamp}");
            Console.WriteLine($"  RequestHeader.RequestHandle: {RequestHeader.RequestHandle}");
            Console.WriteLine($"  RequestHeader.ReturnDiagnostics: {RequestHeader.ReturnDiagnostics}");
            Console.WriteLine($"  RequestHeader.AuditEntryId: {RequestHeader.AuditEntryId ?? "null"}");
            Console.WriteLine($"  RequestHeader.TimeoutHint: {RequestHeader.TimeoutHint}");
            Console.WriteLine($"  ClientProtocolVersion: 0");
            Console.WriteLine($"  RequestType: {Parameters.RequestType} ({(int)Parameters.RequestType})");
            Console.WriteLine($"  SecurityMode: {Parameters.SecurityMode} ({(int)Parameters.SecurityMode})");
            Console.WriteLine($"  ClientNonce: {(Parameters.ClientNonce?.Length ?? -1)} bytes");
            Console.WriteLine($"  RequestedLifetime: {Parameters.RequestedLifetime}");
        }
    }

    /// <summary>
    /// Represents the OpenSecureChannel service response returned by the server.
    /// </summary>
    public class OpenSecureChannelResponse : IDecodable<OpenSecureChannelResponse>, IServiceResponse
    {
        /// <summary>Gets or sets the service response header.</summary>
        public ResponseHeader ResponseHeader { get; set; } = null!;

        /// <summary>Gets or sets the OpenSecureChannel result containing the security token.</summary>
        public OpenSecureChannelResult Parameters { get; set; } = null!;

        /// <summary>
        /// Decodes an <see cref="OpenSecureChannelResponse"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="OpenSecureChannelResponse"/>.</returns>
        public static OpenSecureChannelResponse Decode(BinaryDecoder decoder)
        {
            decoder.CheckServiceFault();
            return new OpenSecureChannelResponse
            {
                ResponseHeader = ResponseHeader.Decode(decoder),
                Parameters = new OpenSecureChannelResult
                {
                    ServerProtocolVersion = decoder.ReadUInt32(),
                    SecurityToken = new ChannelSecurityToken
                    {
                        ChannelId = decoder.ReadUInt32(),
                        TokenId = decoder.ReadUInt32(),
                        CreatedAt = decoder.ReadDateTime(),
                        RevisedLifetime = decoder.ReadUInt32()
                    },
                    ServerNonce = decoder.ReadByteString()
                }
            };
        }
    }
}
