using System;
using System.Text;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    /// <summary>
    /// Constants for OPC UA Tcp message type identifiers (3-byte ASCII sequences).
    /// </summary>
    public static class MessageType
    {
        /// <summary>Invalid message type (INV).</summary>
        public static readonly byte[] Invalid = Encoding.ASCII.GetBytes("INV");
        /// <summary>Hello message type (HEL).</summary>
        public static readonly byte[] Hello = Encoding.ASCII.GetBytes("HEL");
        /// <summary>Acknowledge message type (ACK).</summary>
        public static readonly byte[] Acknowledge = Encoding.ASCII.GetBytes("ACK");
        /// <summary>Error message type (ERR).</summary>
        public static readonly byte[] Error = Encoding.ASCII.GetBytes("ERR");
        /// <summary>Secure channel open message type (OPN).</summary>
        public static readonly byte[] SecureOpen = Encoding.ASCII.GetBytes("OPN");
        /// <summary>Secure channel close message type (CLO).</summary>
        public static readonly byte[] SecureClose = Encoding.ASCII.GetBytes("CLO");
        /// <summary>Secure message type (MSG).</summary>
        public static readonly byte[] SecureMessage = Encoding.ASCII.GetBytes("MSG");

        /// <summary>
        /// Converts a 3-byte message type identifier to its ASCII string representation.
        /// </summary>
        /// <param name="messageType">The 3-byte message type identifier.</param>
        /// <returns>The ASCII string representing the message type.</returns>
        public static string ToString(byte[] messageType)
        {
            return Encoding.ASCII.GetString(messageType);
        }

        /// <summary>
        /// Compares two 3-byte message type identifiers for equality.
        /// </summary>
        /// <param name="a">The first message type identifier.</param>
        /// <param name="b">The second message type identifier.</param>
        /// <returns>True if both identifiers are non-null and contain the same bytes; otherwise false.</returns>
        public static bool Equals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;
            return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
        }
    }

    /// <summary>
    /// Constants for OPC UA Tcp chunk type identifiers.
    /// </summary>
    public static class ChunkType
    {
        /// <summary>Invalid chunk type (0).</summary>
        public const byte Invalid = (byte)'0';
        /// <summary>Final/single chunk (F).</summary>
        public const byte Single = (byte)'F';
        /// <summary>Intermediate chunk (C) - more chunks follow.</summary>
        public const byte Intermediate = (byte)'C';
        /// <summary>Abort chunk (A) - the message is being aborted.</summary>
        public const byte Abort = (byte)'A';
    }

    /// <summary>
    /// Represents the OPC UA Tcp message header that prefixes every message chunk.
    /// </summary>
    public class Header
    {
        /// <summary>
        /// Gets or sets the 3-byte message type identifier (e.g., HEL, ACK, OPN, CLO, MSG, ERR, INV).
        /// </summary>
        public byte[] MessageType { get; set; }

        /// <summary>
        /// Gets or sets the chunk type byte (Single, Intermediate, Abort, or Invalid).
        /// </summary>
        public byte ChunkType { get; set; }

        /// <summary>
        /// Gets or sets the secure channel identifier. Only meaningful for secure messages.
        /// </summary>
        public uint ChannelId { get; set; }

        /// <summary>
        /// Gets or sets the body size in bytes (packet size minus header overhead).
        /// </summary>
        public int BodySize { get; set; }

        /// <summary>
        /// Gets or sets the total packet size in bytes (including the header).
        /// </summary>
        public uint PacketSize { get; set; }

        /// <summary>
        /// Initializes a new <see cref="Header"/> with defaults: SecureMessage type, Single chunk, channel 0, empty body.
        /// </summary>
        public Header()
        {
            MessageType = Types.MessageType.SecureMessage;
            ChunkType = Types.ChunkType.Single;
            ChannelId = 0;
            BodySize = 0;
        }

        /// <summary>
        /// Initializes a new <see cref="Header"/> with the specified message and chunk type, channel 0, empty body.
        /// </summary>
        /// <param name="messageType">The 3-byte message type identifier.</param>
        /// <param name="chunkType">The chunk type byte.</param>
        public Header(byte[] messageType, byte chunkType)
        {
            MessageType = messageType;
            ChunkType = chunkType;
            ChannelId = 0;
            BodySize = 0;
        }

        /// <summary>Gets whether this header represents a secure message (MSG).</summary>
        public bool IsSecureMessage => Types.MessageType.Equals(MessageType, Types.MessageType.SecureMessage);

        /// <summary>Gets whether this header represents a secure channel open (OPN).</summary>
        public bool IsSecureOpen => Types.MessageType.Equals(MessageType, Types.MessageType.SecureOpen);

        /// <summary>Gets whether this header represents a secure channel close (CLO).</summary>
        public bool IsSecureClose => Types.MessageType.Equals(MessageType, Types.MessageType.SecureClose);

        /// <summary>Gets whether this header represents a hello message (HEL).</summary>
        public bool IsHello => Types.MessageType.Equals(MessageType, Types.MessageType.Hello);

        /// <summary>Gets whether this header represents an acknowledge message (ACK).</summary>
        public bool IsAcknowledge => Types.MessageType.Equals(MessageType, Types.MessageType.Acknowledge);

        /// <summary>Gets whether this header represents an error message (ERR).</summary>
        public bool IsError => Types.MessageType.Equals(MessageType, Types.MessageType.Error);

        /// <summary>
        /// Encodes this header into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
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

        /// <summary>
        /// Decodes a <see cref="Header"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="Header"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the packet size is invalid.</exception>
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

        /// <summary>
        /// Returns a string representation of the header for diagnostic purposes.
        /// </summary>
        public override string ToString()
        {
            return $"Header(Type={Types.MessageType.ToString(MessageType)}, Chunk={(char)ChunkType}, BodySize={BodySize}, Channel={ChannelId})";
        }
    }

    /// <summary>
    /// Represents the OPC UA Tcp Hello message sent during connection establishment.
    /// Negotiates protocol version, buffer sizes, and the endpoint URL.
    /// </summary>
    public class Hello
    {
        /// <summary>Gets or sets the protocol version.</summary>
        public uint ProtocolVersion { get; set; }

        /// <summary>Gets or sets the receive buffer size in bytes.</summary>
        public uint ReceiveBufferSize { get; set; }

        /// <summary>Gets or sets the send buffer size in bytes.</summary>
        public uint SendBufferSize { get; set; }

        /// <summary>Gets or sets the maximum message size in bytes (0 means unlimited).</summary>
        public uint MaxMessageSize { get; set; }

        /// <summary>Gets or sets the maximum chunk count per message.</summary>
        public uint MaxChunkCount { get; set; }

        /// <summary>Gets or sets the endpoint URL.</summary>
        public string? EndpointUrl { get; set; }

        /// <summary>
        /// Initializes a new <see cref="Hello"/> with default buffer sizes of 65536 bytes.
        /// </summary>
        public Hello()
        {
            ProtocolVersion = 0;
            ReceiveBufferSize = 65536;
            SendBufferSize = 65536;
            MaxMessageSize = 0;
            MaxChunkCount = 0;
            EndpointUrl = "";
        }

        /// <summary>
        /// Encodes this Hello message into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(ProtocolVersion);
            encoder.WriteUInt32(ReceiveBufferSize);
            encoder.WriteUInt32(SendBufferSize);
            encoder.WriteUInt32(MaxMessageSize);
            encoder.WriteUInt32(MaxChunkCount);
            encoder.WriteString(EndpointUrl ?? "");
        }

        /// <summary>
        /// Decodes a <see cref="Hello"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="Hello"/>.</returns>
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

    /// <summary>
    /// Represents the OPC UA Tcp Acknowledge message sent in response to a Hello.
    /// </summary>
    public class Acknowledge
    {
        /// <summary>Gets or sets the protocol version.</summary>
        public uint ProtocolVersion { get; set; }

        /// <summary>Gets or sets the receive buffer size in bytes.</summary>
        public uint ReceiveBufferSize { get; set; }

        /// <summary>Gets or sets the send buffer size in bytes.</summary>
        public uint SendBufferSize { get; set; }

        /// <summary>Gets or sets the maximum message size in bytes (0 means unlimited).</summary>
        public uint MaxMessageSize { get; set; }

        /// <summary>Gets or sets the maximum chunk count per message.</summary>
        public uint MaxChunkCount { get; set; }

        /// <summary>
        /// Initializes a new <see cref="Acknowledge"/> with default buffer sizes of 65536 bytes.
        /// </summary>
        public Acknowledge()
        {
            ProtocolVersion = 0;
            ReceiveBufferSize = 65536;
            SendBufferSize = 65536;
            MaxMessageSize = 0;
            MaxChunkCount = 0;
        }

        /// <summary>
        /// Encodes this Acknowledge message into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(ProtocolVersion);
            encoder.WriteUInt32(ReceiveBufferSize);
            encoder.WriteUInt32(SendBufferSize);
            encoder.WriteUInt32(MaxMessageSize);
            encoder.WriteUInt32(MaxChunkCount);
        }

        /// <summary>
        /// Decodes an <see cref="Acknowledge"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="Acknowledge"/>.</returns>
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

    /// <summary>
    /// Represents the OPC UA Tcp Error message, transmitted when a communication error occurs.
    /// </summary>
    public class ErrorMessage
    {
        /// <summary>Gets or sets the status code indicating the error.</summary>
        public StatusCode Error { get; set; }

        /// <summary>Gets or sets a human-readable description of the error.</summary>
        public string? Reason { get; set; }

        /// <summary>
        /// Initializes a new <see cref="ErrorMessage"/> with no error and an empty reason.
        /// </summary>
        public ErrorMessage()
        {
            Error = new StatusCode();
            Reason = "";
        }

        /// <summary>
        /// Encodes this error message into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(Error.Value);
            encoder.WriteString(Reason ?? "");
        }

        /// <summary>
        /// Decodes an <see cref="ErrorMessage"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="ErrorMessage"/>.</returns>
        public static ErrorMessage Decode(BinaryDecoder decoder)
        {
            return new ErrorMessage
            {
                Error = new StatusCode(decoder.ReadUInt32()),
                Reason = decoder.ReadString()
            };
        }

        /// <summary>
        /// Returns a string representation of the error for diagnostic purposes.
        /// </summary>
        public override string ToString()
        {
            return $"ErrorMessage(Error={Error}, Reason={Reason})";
        }
    }

    /// <summary>
    /// Represents the OPC UA Sequence Header that follows the security header in every secure message chunk.
    /// Contains the sequence number for message ordering and the request identifier.
    /// </summary>
    public class SequenceHeader
    {
        /// <summary>Gets or sets the monotonically increasing sequence number for detecting lost or replayed messages.</summary>
        public uint SequenceNumber { get; set; }

        /// <summary>Gets or sets the request identifier assigned by the client.</summary>
        public uint RequestId { get; set; }

        /// <summary>
        /// Initializes a new <see cref="SequenceHeader"/> with sequence number 1 and request id 1.
        /// </summary>
        public SequenceHeader()
        {
            SequenceNumber = 1;
            RequestId = 1;
        }

        /// <summary>
        /// Encodes this sequence header into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(SequenceNumber);
            encoder.WriteUInt32(RequestId);
        }

        /// <summary>
        /// Decodes a <see cref="SequenceHeader"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="SequenceHeader"/>.</returns>
        public static SequenceHeader Decode(BinaryDecoder decoder)
        {
            return new SequenceHeader
            {
                SequenceNumber = decoder.ReadUInt32(),
                RequestId = decoder.ReadUInt32()
            };
        }

        /// <summary>
        /// Returns a string representation of the sequence header for diagnostic purposes.
        /// </summary>
        public override string ToString()
        {
            return $"SequenceHeader(Seq={SequenceNumber}, ReqId={RequestId})";
        }
    }

    /// <summary>
    /// A message chunk security header (symmetric or asymmetric) that can encode itself.
    /// Lets the transport treat both header kinds uniformly instead of type-switching on object.
    /// </summary>
    public interface ISecurityHeader
    {
        /// <summary>Encodes this security header into the given <paramref name="encoder"/>.</summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        void Encode(BinaryEncoder encoder);
    }

    /// <summary>
    /// Represents the OPC UA Symmetric Algorithm Security Header that precedes the sequence header in secure message chunks.
    /// Identifies the security token used for encryption and signing.
    /// </summary>
    public class SymmetricAlgorithmHeader : ISecurityHeader
    {
        /// <summary>Gets or sets the security token identifier.</summary>
        public uint TokenId { get; set; }

        /// <summary>
        /// Initializes a new <see cref="SymmetricAlgorithmHeader"/> with token id 0.
        /// </summary>
        public SymmetricAlgorithmHeader()
        {
            TokenId = 0;
        }

        /// <summary>
        /// Encodes this symmetric algorithm header into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt32(TokenId);
        }

        /// <summary>
        /// Decodes a <see cref="SymmetricAlgorithmHeader"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="SymmetricAlgorithmHeader"/>.</returns>
        public static SymmetricAlgorithmHeader Decode(BinaryDecoder decoder)
        {
            return new SymmetricAlgorithmHeader
            {
                TokenId = decoder.ReadUInt32()
            };
        }

        /// <summary>
        /// Returns a string representation of the symmetric algorithm header for diagnostic purposes.
        /// </summary>
        public override string ToString()
        {
            return $"SymmetricAlgorithmHeader(TokenId={TokenId})";
        }
    }

    /// <summary>
    /// Represents the OPC UA Asymmetric Algorithm Security Header used during OpenSecureChannel.
    /// Contains the security policy URI and X.509 certificate data for establishing the secure channel.
    /// </summary>
    public class AsymmetricAlgorithmHeader : ISecurityHeader
    {
        /// <summary>Gets or sets the security policy URI (e.g., http://opcfoundation.org/UA/SecurityPolicy#None).</summary>
        public string? SecurityPolicyUri { get; set; }

        /// <summary>Gets or sets the DER-encoded sender X.509 certificate, or null for no certificate.</summary>
        public byte[]? SenderCertificate { get; set; }

        /// <summary>Gets or sets the thumbprint of the receiver X.509 certificate.</summary>
        public byte[]? ReceiverCertificateThumbprint { get; set; }

        /// <summary>
        /// Initializes a new <see cref="AsymmetricAlgorithmHeader"/> with the None security policy and no certificates.
        /// </summary>
        public AsymmetricAlgorithmHeader()
        {
            SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
            SenderCertificate = null;
            ReceiverCertificateThumbprint = null;
        }

        /// <summary>
        /// Encodes this asymmetric algorithm header into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteString(SecurityPolicyUri ?? "");
            encoder.WriteByteString(SenderCertificate);
            encoder.WriteByteString(ReceiverCertificateThumbprint);
        }

        /// <summary>
        /// Decodes an <see cref="AsymmetricAlgorithmHeader"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="AsymmetricAlgorithmHeader"/>.</returns>
        public static AsymmetricAlgorithmHeader Decode(BinaryDecoder decoder)
        {
            return new AsymmetricAlgorithmHeader
            {
                SecurityPolicyUri = decoder.ReadString(),
                SenderCertificate = decoder.ReadByteString(),
                ReceiverCertificateThumbprint = decoder.ReadByteString()
            };
        }

        /// <summary>
        /// Returns a string representation of the asymmetric algorithm header for diagnostic purposes.
        /// </summary>
        public override string ToString()
        {
            return $"AsymmetricAlgorithmHeader(Policy={SecurityPolicyUri})";
        }
    }
}
