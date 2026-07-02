using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Transport;
using TinyUa.Core.Types;

namespace TinyUa.Core.Client.Services
{
    public class RequestHeader : IEncodable
    {
        public NodeId AuthenticationToken { get; set; } = new NodeId();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public uint RequestHandle { get; set; }
        public uint ReturnDiagnostics { get; set; }
        public string? AuditEntryId { get; set; }
        public uint TimeoutHint { get; set; } = 0;
        public ExtensionObject? AdditionalHeader { get; set; }

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

    public class ResponseHeader : IDecodable<ResponseHeader>
    {
        public DateTime Timestamp { get; set; }
        public uint RequestHandle { get; set; }
        public StatusCode ServiceResult { get; set; } = new StatusCode();
        public DiagnosticInfo? ServiceDiagnostics { get; set; }
        public string[]? StringTable { get; set; }
        public ExtensionObject? AdditionalHeader { get; set; }

        public static ResponseHeader Decode(BinaryDecoder decoder)
        {
            var header = new ResponseHeader
            {
                Timestamp = decoder.ReadDateTime(),
                RequestHandle = decoder.ReadUInt32(),
                ServiceResult = new StatusCode(decoder.ReadUInt32())
            };

            var diEncoding = decoder.ReadByte();
            if (diEncoding != 0)
            {

                if ((diEncoding & 0x01) != 0) decoder.ReadInt32();
                if ((diEncoding & 0x02) != 0) decoder.ReadInt32();
                if ((diEncoding & 0x04) != 0) decoder.ReadString();
                if ((diEncoding & 0x08) != 0) decoder.ReadString();
                if ((diEncoding & 0x10) != 0) decoder.ReadByte();
                if ((diEncoding & 0x20) != 0) decoder.ReadInt32();
                if ((diEncoding & 0x40) != 0) decoder.ReadInt32();
                if ((diEncoding & 0x80) != 0) { }
            }

            var stringCount = decoder.ReadInt32();
            for (int i = 0; i < stringCount; i++)
            {
                decoder.ReadString();
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

    public class DiagnosticInfo
    {
    }

    public class OpenSecureChannelRequest : IEncodable
    {
        public RequestHeader RequestHeader { get; set; } = new RequestHeader();
        public OpenSecureChannelParameters Parameters { get; set; } = new OpenSecureChannelParameters();

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

    public class OpenSecureChannelResponse : IDecodable<OpenSecureChannelResponse>
    {
        public ResponseHeader ResponseHeader { get; set; } = null!;
        public OpenSecureChannelResult Parameters { get; set; } = null!;

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
