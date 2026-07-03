using System;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    /// <summary>
    /// Enumerates the OPC UA node classes, used to describe the kind of a node in the address space.
    /// Values may be combined as flags.
    /// </summary>
    public enum NodeClass
    {
        /// <summary>Unspecified node class.</summary>
        Unspecified = 0,
        /// <summary>An Object node.</summary>
        Object = 1,
        /// <summary>A Variable node.</summary>
        Variable = 2,
        /// <summary>A Method node.</summary>
        Method = 4,
        /// <summary>An ObjectType node.</summary>
        ObjectType = 8,
        /// <summary>A VariableType node.</summary>
        VariableType = 16,
        /// <summary>A ReferenceType node.</summary>
        ReferenceType = 32,
        /// <summary>A DataType node.</summary>
        DataType = 64,
        /// <summary>A View node.</summary>
        View = 128
    }

    /// <summary>
    /// Represents an OPC UA StatusCode, a 32-bit value carrying quality and diagnostic information.
    /// </summary>
    public readonly struct StatusCode : IEquatable<StatusCode>
    {
        /// <summary>
        /// Gets the raw 32-bit status code value.
        /// </summary>
        public uint Value { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="StatusCode"/> struct.
        /// </summary>
        /// <param name="value">The raw status code value. Defaults to <c>Good</c> (0).</param>
        public StatusCode(uint value = 0)
        {
            Value = value;
        }

        /// <summary>
        /// Gets a value indicating whether the status is Good (highest two bits are 0).
        /// </summary>
        public bool IsGood => (Value & 0xC0000000) == 0;

        /// <summary>
        /// Gets a value indicating whether the status is Uncertain (second-highest bit set).
        /// </summary>
        public bool IsUncertain => (Value & 0x40000000) != 0;

        /// <summary>
        /// Gets a value indicating whether the status is Bad (highest bit set).
        /// </summary>
        public bool IsBad => (Value & 0x80000000) != 0;

        /// <summary>
        /// Throws a <see cref="UaException"/> if the status code is not Good.
        /// </summary>
        public void Check()
        {
            if (!IsGood)
                throw new UaException(Value);
        }

        /// <summary>
        /// Determines whether the current status code equals another.
        /// </summary>
        /// <param name="other">The other status code to compare.</param>
        /// <returns><c>true</c> if the raw values are equal; otherwise <c>false</c>.</returns>
        public bool Equals(StatusCode other) => Value == other.Value;

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is StatusCode other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => Value.GetHashCode();

        /// <summary>
        /// Determines whether two <see cref="StatusCode"/> values are equal.
        /// </summary>
        public static bool operator ==(StatusCode left, StatusCode right) => left.Value == right.Value;

        /// <summary>
        /// Determines whether two <see cref="StatusCode"/> values are not equal.
        /// </summary>
        public static bool operator !=(StatusCode left, StatusCode right) => left.Value != right.Value;

        /// <summary>
        /// Returns the hexadecimal string representation of the status code.
        /// </summary>
        /// <returns>A string like "StatusCode(0x00000000)".</returns>
        public override string ToString()
        {
            return $"StatusCode(0x{Value:X8})";
        }

        /// <summary>
        /// A Good status code (0x00000000).
        /// </summary>
        public static StatusCode Good => new StatusCode(0);

        /// <summary>
        /// A generic Bad status code (0x80000000).
        /// </summary>
        public static StatusCode Bad => new StatusCode(0x80000000);
    }

    /// <summary>
    /// Represents an OPC UA QualifiedName, a name qualified by a namespace index.
    /// </summary>
    public class QualifiedName
    {
        /// <summary>
        /// Gets or sets the namespace index.
        /// </summary>
        public ushort NamespaceIndex { get; set; }

        /// <summary>
        /// Gets or sets the name portion of the qualified name.
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="QualifiedName"/> class with default values.
        /// </summary>
        public QualifiedName()
        {
            NamespaceIndex = 0;
            Name = null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="QualifiedName"/> class.
        /// </summary>
        /// <param name="name">The name portion.</param>
        /// <param name="namespaceIndex">The namespace index (default 0).</param>
        public QualifiedName(string? name, ushort namespaceIndex = 0)
        {
            NamespaceIndex = namespaceIndex;
            Name = name;
        }

        /// <summary>
        /// Returns a string in the form "ns:name".
        /// </summary>
        public override string ToString()
        {
            return $"{NamespaceIndex}:{Name}";
        }

        /// <summary>
        /// Encodes this qualified name into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt16(NamespaceIndex);
            encoder.WriteString(Name ?? "");
        }

        /// <summary>
        /// Decodes a <see cref="QualifiedName"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="QualifiedName"/> decoded from the stream.</returns>
        public static QualifiedName Decode(BinaryDecoder decoder)
        {
            return new QualifiedName
            {
                NamespaceIndex = decoder.ReadUInt16(),
                Name = decoder.ReadString()
            };
        }
    }

    /// <summary>
    /// Represents an OPC UA LocalizedText, a human-readable text string with an optional locale identifier.
    /// </summary>
    public class LocalizedText
    {
        private string? _locale;
        private string? _text;
        private byte _encoding;

        /// <summary>
        /// Gets or sets the locale identifier (e.g. "en-US"). Setting this updates the encoding mask.
        /// </summary>
        public string? Locale
        {
            get => _locale;
            set
            {
                _locale = value;
                if (!string.IsNullOrEmpty(value))
                    _encoding |= 0x01;
                else
                    _encoding &= 0xFE;
            }
        }

        /// <summary>
        /// Gets or sets the text value. Setting this updates the encoding mask.
        /// </summary>
        public string? Text
        {
            get => _text;
            set
            {
                _text = value;
                if (!string.IsNullOrEmpty(value))
                    _encoding |= 0x02;
                else
                    _encoding &= 0xFD;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalizedText"/> class with default values.
        /// </summary>
        public LocalizedText()
        {
            _encoding = 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalizedText"/> class.
        /// </summary>
        /// <param name="text">The text value.</param>
        /// <param name="locale">The optional locale identifier.</param>
        public LocalizedText(string? text, string? locale = null)
        {
            Text = text;
            Locale = locale;
        }

        /// <summary>
        /// Returns a string in the form "[locale] text" or just "text" if no locale is set.
        /// </summary>
        public override string ToString()
        {
            if (string.IsNullOrEmpty(Locale))
                return Text ?? string.Empty;
            return $"[{Locale}] {Text}";
        }

        /// <summary>
        /// Encodes this localized text into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteByte(_encoding);
            if ((_encoding & 0x01) != 0)
                encoder.WriteString(Locale ?? "");
            if ((_encoding & 0x02) != 0)
                encoder.WriteString(Text ?? "");
        }

        /// <summary>
        /// Decodes a <see cref="LocalizedText"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="LocalizedText"/> decoded from the stream.</returns>
        public static LocalizedText Decode(BinaryDecoder decoder)
        {
            var encoding = decoder.ReadByte();
            var text = new LocalizedText();

            if ((encoding & 0x01) != 0)
                text._locale = decoder.ReadString();
            if ((encoding & 0x02) != 0)
                text._text = decoder.ReadString();

            text._encoding = encoding;
            return text;
        }
    }

    /// <summary>
    /// Represents an OPC UA DataValue, combining a value with a status code and optional timestamps.
    /// </summary>
    public class DataValue
    {
        private byte _encoding;

        /// <summary>
        /// Gets or sets the variant value.
        /// </summary>
        public Variant? Value { get; set; }

        /// <summary>
        /// Gets or sets the status code associated with the value.
        /// </summary>
        public StatusCode? StatusCode { get; set; }

        /// <summary>
        /// Gets or sets the source timestamp of the value.
        /// </summary>
        public DateTime? SourceTimestamp { get; set; }

        /// <summary>
        /// Gets or sets the sub-millisecond source timestamp in picoseconds.
        /// </summary>
        public ushort? SourcePicoseconds { get; set; }

        /// <summary>
        /// Gets or sets the server timestamp of the value.
        /// </summary>
        public DateTime? ServerTimestamp { get; set; }

        /// <summary>
        /// Gets or sets the sub-millisecond server timestamp in picoseconds.
        /// </summary>
        public ushort? ServerPicoseconds { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DataValue"/> class with a Good status code.
        /// </summary>
        public DataValue()
        {
            StatusCode = new StatusCode();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DataValue"/> class.
        /// </summary>
        /// <param name="value">The variant value.</param>
        /// <param name="status">The status code. Defaults to Good if null.</param>
        public DataValue(Variant? value, StatusCode? status = null)
        {
            Value = value;
            StatusCode = status ?? new StatusCode();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DataValue"/> class with a CLR value that is wrapped in a <see cref="Variant"/>.
        /// </summary>
        /// <param name="value">The CLR value to wrap.</param>
        /// <param name="type">The optional explicit OPC UA variant type.</param>
        public DataValue(object? value, VariantType? type = null)
        {
            Value = new Variant(value, type);
            StatusCode = new StatusCode();
        }

        /// <summary>
        /// Returns a string describing this data value.
        /// </summary>
        public override string ToString()
        {
            return $"DataValue({Value}, {StatusCode})";
        }

        /// <summary>
        /// Encodes this data value into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            _encoding = 0;

            if (Value != null && Value.VariantType != VariantType.Null)
                _encoding |= 0x01;
            if (StatusCode != null && StatusCode.Value.Value != 0)
                _encoding |= 0x02;
            if (SourceTimestamp.HasValue)
                _encoding |= 0x04;
            if (ServerTimestamp.HasValue)
                _encoding |= 0x08;
            if (SourcePicoseconds.HasValue)
                _encoding |= 0x10;
            if (ServerPicoseconds.HasValue)
                _encoding |= 0x20;

            encoder.WriteByte(_encoding);

            if ((_encoding & 0x01) != 0)
                VariantCodec.Encode(encoder, Value);
            if ((_encoding & 0x02) != 0)
                encoder.WriteUInt32(StatusCode!.Value.Value);
            if ((_encoding & 0x04) != 0)
                encoder.WriteDateTime(SourceTimestamp!.Value);
            if ((_encoding & 0x08) != 0)
                encoder.WriteDateTime(ServerTimestamp!.Value);
            if ((_encoding & 0x10) != 0)
                encoder.WriteUInt16(SourcePicoseconds!.Value);
            if ((_encoding & 0x20) != 0)
                encoder.WriteUInt16(ServerPicoseconds!.Value);
        }

        /// <summary>
        /// Decodes a <see cref="DataValue"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="DataValue"/> decoded from the stream.</returns>
        public static DataValue Decode(BinaryDecoder decoder)
        {
            var encoding = decoder.ReadByte();
            var dv = new DataValue();

            if ((encoding & 0x01) != 0)
                dv.Value = VariantCodec.Decode(decoder);
            if ((encoding & 0x02) != 0)
                dv.StatusCode = new StatusCode(decoder.ReadUInt32());
            if ((encoding & 0x04) != 0)
                dv.SourceTimestamp = decoder.ReadDateTime();
            if ((encoding & 0x08) != 0)
                dv.ServerTimestamp = decoder.ReadDateTime();
            if ((encoding & 0x10) != 0)
                dv.SourcePicoseconds = decoder.ReadUInt16();
            if ((encoding & 0x20) != 0)
                dv.ServerPicoseconds = decoder.ReadUInt16();

            return dv;
        }
    }

    /// <summary>
    /// Represents an OPC UA ExtensionObject, carrying a type-identified opaque body with an encoding indicator.
    /// </summary>
    public class ExtensionObject
    {
        /// <summary>
        /// Gets or sets the type identifier for the encoded body.
        /// </summary>
        public NodeId? TypeId { get; set; }

        /// <summary>
        /// Gets or sets the encoding byte (0 = none, 1 = binary, 2 = XML).
        /// </summary>
        public byte Encoding { get; set; }

        /// <summary>
        /// Gets or sets the encoded body bytes. May be null if no body is present.
        /// </summary>
        public byte[]? Body { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExtensionObject"/> class with default values.
        /// </summary>
        public ExtensionObject()
        {
            TypeId = new NodeId();
            Encoding = 0;
            Body = null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExtensionObject"/> class.
        /// </summary>
        /// <param name="typeId">The type identifier for the encoded body.</param>
        /// <param name="body">The encoded body bytes. If non-null, encoding is set to 1 (binary).</param>
        public ExtensionObject(NodeId? typeId, byte[]? body)
        {
            TypeId = typeId;
            Body = body;
            Encoding = body != null ? (byte)1 : (byte)0;
        }

        /// <summary>
        /// Encodes this extension object into the OPC UA binary format.
        /// </summary>
        /// <param name="encoder">The binary encoder to write to.</param>
        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, TypeId);
            encoder.WriteByte(Encoding);
            if (Encoding == 1 && Body != null)
            {
                encoder.WriteByteString(Body);
            }
        }

        /// <summary>
        /// Decodes an <see cref="ExtensionObject"/> from the OPC UA binary format.
        /// </summary>
        /// <param name="decoder">The binary decoder to read from.</param>
        /// <returns>A new <see cref="ExtensionObject"/> decoded from the stream.</returns>
        public static ExtensionObject Decode(BinaryDecoder decoder)
        {
            var obj = new ExtensionObject();
            obj.TypeId = NodeIdCodec.Decode(decoder);
            obj.Encoding = decoder.ReadByte();

            if ((obj.Encoding & 0x01) != 0)
            {
                obj.Body = decoder.ReadByteString();
            }

            return obj;
        }
    }

    /// <summary>
    /// Represents an OPC UA service fault exception. Thrown when a service call returns an error status code.
    /// </summary>
    public class UaException : Exception
    {
        /// <summary>
        /// Gets the OPC UA status code that caused this exception.
        /// </summary>
        public uint StatusCode { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="UaException"/> class with a status code.
        /// </summary>
        /// <param name="statusCode">The OPC UA status code.</param>
        public UaException(uint statusCode) : base($"OPC UA Error: 0x{statusCode:X8}")
        {
            StatusCode = statusCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UaException"/> class with a status code and a custom message.
        /// </summary>
        /// <param name="statusCode">The OPC UA status code.</param>
        /// <param name="message">A custom error message.</param>
        public UaException(uint statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}
