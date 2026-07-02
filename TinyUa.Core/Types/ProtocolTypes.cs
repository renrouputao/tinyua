using System;
using System.Text;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    public static class MessageType
    {
        public static readonly byte[] Invalid = Encoding.ASCII.GetBytes("INV");
        public static readonly byte[] Hello = Encoding.ASCII.GetBytes("HEL");
        public static readonly byte[] Acknowledge = Encoding.ASCII.GetBytes("ACK");
        public static readonly byte[] Error = Encoding.ASCII.GetBytes("ERR");
        public static readonly byte[] SecureOpen = Encoding.ASCII.GetBytes("OPN");
        public static readonly byte[] SecureClose = Encoding.ASCII.GetBytes("CLO");
        public static readonly byte[] SecureMessage = Encoding.ASCII.GetBytes("MSG");

        public static string ToString(byte[] messageType)
        {
            return Encoding.ASCII.GetString(messageType);
        }

        public static bool Equals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;
            return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
        }
    }

    public static class ChunkType
    {
        public const byte Invalid = (byte)'0';
        public const byte Single = (byte)'F';
        public const byte Intermediate = (byte)'C';
        public const byte Abort = (byte)'A';
    }

    public class Header
    {
        public byte[] MessageType { get; set; }
        public byte ChunkType { get; set; }
        public uint ChannelId { get; set; }
        public int BodySize { get; set; }
        public uint PacketSize { get; set; }

        public Header()
        {
            MessageType = Types.MessageType.SecureMessage;
            ChunkType = Types.ChunkType.Single;
            ChannelId = 0;
            BodySize = 0;
        }

        public Header(byte[] messageType, byte chunkType)
        {
            MessageType = messageType;
            ChunkType = chunkType;
            ChannelId = 0;
            BodySize = 0;
        }

        public bool IsSecureMessage => Types.MessageType.Equals(MessageType, Types.MessageType.SecureMessage);
        public bool IsSecureOpen => Types.MessageType.Equals(MessageType, Types.MessageType.SecureOpen);
        public bool IsSecureClose => Types.MessageType.Equals(MessageType, Types.MessageType.SecureClose);
        public bool IsHello => Types.MessageType.Equals(MessageType, Types.MessageType.Hello);
        public bool IsAcknowledge => Types.MessageType.Equals(MessageType, Types.MessageType.Acknowledge);
        public bool IsError => Types.MessageType.Equals(MessageType, Types.MessageType.Error);

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteBytes(MessageType);
            encoder.WriteByte(ChunkType);

            var size = BodySize + 8;
            if (IsSecureMessage || IsSecureOpen || IsSecureClose)
            {
                size += 4;
            }

            encoder.WriteUInt32((uint)size);

            if (IsSecureMessage || IsSecureOpen || IsSecureClose)
            {
                encoder.WriteUInt32(ChannelId);
            }
        }

        public static Header Decode(BinaryDecoder decoder)
        {
            var header = new Header();

            header.MessageType = decoder.ReadBytes(3);
            header.ChunkType = decoder.ReadByte();
            header.PacketSize = decoder.ReadUInt32();

            if (header.PacketSize < 8)
                throw new InvalidOperationException($"Invalid PacketSize: {header.PacketSize} (minimum 8)");

            header.BodySize = (int)header.PacketSize - 8;

            if (header.IsSecureMessage || header.IsSecureOpen || header.IsSecureClose)
            {
                if (header.PacketSize < 12)
                    throw new InvalidOperationException($"Invalid PacketSize for secure message: {header.PacketSize} (minimum 12)");
                header.BodySize -= 4;
            }

            return header;
        }

        public override string ToString()
        {
            return $"Header(Type={Types.MessageType.ToString(MessageType)}, Chunk={(char)ChunkType}, BodySize={BodySize}, Channel={ChannelId})";
        }
    }

    public class Hello
    {
        public uint ProtocolVersion { get; set; }
        public uint ReceiveBufferSize { get; set; }
        public uint SendBufferSize { get; set; }
        public uint MaxMessageSize { get; set; }
        public uint MaxChunkCount { get; set; }
        public string? EndpointUrl { get; set; }

        public Hello()
        {
            ProtocolVersion = 0;
            ReceiveBufferSize = 65536;
            SendBufferSize = 65536;
            MaxMessageSize = 0;
            MaxChunkCount = 0;
            EndpointUrl = "";
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(ProtocolVersion);
            encoder.WriteUInt32(ReceiveBufferSize);
            encoder.WriteUInt32(SendBufferSize);
            encoder.WriteUInt32(MaxMessageSize);
            encoder.WriteUInt32(MaxChunkCount);
            encoder.WriteString(EndpointUrl ?? "");
        }

        public static Hello Decode(BinaryDecoder decoder)
        {
            return new Hello
            {
                ProtocolVersion = decoder.ReadUInt32(),
                ReceiveBufferSize = decoder.ReadUInt32(),
                SendBufferSize = decoder.ReadUInt32(),
                MaxMessageSize = decoder.ReadUInt32(),
                MaxChunkCount = decoder.ReadUInt32(),
                EndpointUrl = decoder.ReadString()
            };
        }
    }

    public class Acknowledge
    {
        public uint ProtocolVersion { get; set; }
        public uint ReceiveBufferSize { get; set; }
        public uint SendBufferSize { get; set; }
        public uint MaxMessageSize { get; set; }
        public uint MaxChunkCount { get; set; }

        public Acknowledge()
        {
            ProtocolVersion = 0;
            ReceiveBufferSize = 65536;
            SendBufferSize = 65536;
            MaxMessageSize = 0;
            MaxChunkCount = 0;
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(ProtocolVersion);
            encoder.WriteUInt32(ReceiveBufferSize);
            encoder.WriteUInt32(SendBufferSize);
            encoder.WriteUInt32(MaxMessageSize);
            encoder.WriteUInt32(MaxChunkCount);
        }

        public static Acknowledge Decode(BinaryDecoder decoder)
        {
            return new Acknowledge
            {
                ProtocolVersion = decoder.ReadUInt32(),
                ReceiveBufferSize = decoder.ReadUInt32(),
                SendBufferSize = decoder.ReadUInt32(),
                MaxMessageSize = decoder.ReadUInt32(),
                MaxChunkCount = decoder.ReadUInt32()
            };
        }
    }

    public class ErrorMessage
    {
        public StatusCode Error { get; set; }
        public string? Reason { get; set; }

        public ErrorMessage()
        {
            Error = new StatusCode();
            Reason = "";
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(Error.Value);
            encoder.WriteString(Reason ?? "");
        }

        public static ErrorMessage Decode(BinaryDecoder decoder)
        {
            return new ErrorMessage
            {
                Error = new StatusCode(decoder.ReadUInt32()),
                Reason = decoder.ReadString()
            };
        }

        public override string ToString()
        {
            return $"ErrorMessage(Error={Error}, Reason={Reason})";
        }
    }

    public class SequenceHeader
    {
        public uint SequenceNumber { get; set; }
        public uint RequestId { get; set; }

        public SequenceHeader()
        {
            SequenceNumber = 1;
            RequestId = 1;
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SequenceNumber);
            encoder.WriteUInt32(RequestId);
        }

        public static SequenceHeader Decode(BinaryDecoder decoder)
        {
            return new SequenceHeader
            {
                SequenceNumber = decoder.ReadUInt32(),
                RequestId = decoder.ReadUInt32()
            };
        }

        public override string ToString()
        {
            return $"SequenceHeader(Seq={SequenceNumber}, ReqId={RequestId})";
        }
    }

    public class SymmetricAlgorithmHeader
    {
        public uint TokenId { get; set; }

        public SymmetricAlgorithmHeader()
        {
            TokenId = 0;
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(TokenId);
        }

        public static SymmetricAlgorithmHeader Decode(BinaryDecoder decoder)
        {
            return new SymmetricAlgorithmHeader
            {
                TokenId = decoder.ReadUInt32()
            };
        }

        public override string ToString()
        {
            return $"SymmetricAlgorithmHeader(TokenId={TokenId})";
        }
    }

    public class AsymmetricAlgorithmHeader
    {
        public string? SecurityPolicyUri { get; set; }
        public byte[]? SenderCertificate { get; set; }
        public byte[]? ReceiverCertificateThumbprint { get; set; }

        public AsymmetricAlgorithmHeader()
        {
            SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
            SenderCertificate = null;
            ReceiverCertificateThumbprint = null;
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString(SecurityPolicyUri ?? "");
            encoder.WriteByteString(SenderCertificate);
            encoder.WriteByteString(ReceiverCertificateThumbprint);
        }

        public static AsymmetricAlgorithmHeader Decode(BinaryDecoder decoder)
        {
            return new AsymmetricAlgorithmHeader
            {
                SecurityPolicyUri = decoder.ReadString(),
                SenderCertificate = decoder.ReadByteString(),
                ReceiverCertificateThumbprint = decoder.ReadByteString()
            };
        }

        public override string ToString()
        {
            return $"AsymmetricAlgorithmHeader(Policy={SecurityPolicyUri})";
        }
    }
}
