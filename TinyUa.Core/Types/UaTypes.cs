using System;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    public enum NodeClass
    {
        Unspecified = 0,
        Object = 1,
        Variable = 2,
        Method = 4,
        ObjectType = 8,
        VariableType = 16,
        ReferenceType = 32,
        DataType = 64,
        View = 128
    }

    public readonly struct StatusCode : IEquatable<StatusCode>
    {
        public uint Value { get; }

        public StatusCode(uint value = 0)
        {
            Value = value;
        }

        public bool IsGood => (Value & 0xC0000000) == 0;
        public bool IsUncertain => (Value & 0x40000000) != 0;
        public bool IsBad => (Value & 0x80000000) != 0;

        public void Check()
        {
            if (!IsGood)
                throw new UaException(Value);
        }

        public bool Equals(StatusCode other) => Value == other.Value;
        public override bool Equals(object? obj) => obj is StatusCode other && Equals(other);
        public override int GetHashCode() => Value.GetHashCode();
        public static bool operator ==(StatusCode left, StatusCode right) => left.Value == right.Value;
        public static bool operator !=(StatusCode left, StatusCode right) => left.Value != right.Value;

        public override string ToString()
        {
            return $"StatusCode(0x{Value:X8})";
        }

        public static StatusCode Good => new StatusCode(0);
        public static StatusCode Bad => new StatusCode(0x80000000);
    }

    public class QualifiedName
    {
        public ushort NamespaceIndex { get; set; }
        public string? Name { get; set; }

        public QualifiedName()
        {
            NamespaceIndex = 0;
            Name = null;
        }

        public QualifiedName(string? name, ushort namespaceIndex = 0)
        {
            NamespaceIndex = namespaceIndex;
            Name = name;
        }

        public override string ToString()
        {
            return $"{NamespaceIndex}:{Name}";
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteUInt16(NamespaceIndex);
            encoder.WriteString(Name ?? "");
        }

        public static QualifiedName Decode(BinaryDecoder decoder)
        {
            return new QualifiedName
            {
                NamespaceIndex = decoder.ReadUInt16(),
                Name = decoder.ReadString()
            };
        }
    }

    public class LocalizedText
    {
        private string? _locale;
        private string? _text;
        private byte _encoding;

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

        public LocalizedText()
        {
            _encoding = 0;
        }

        public LocalizedText(string? text, string? locale = null)
        {
            Text = text;
            Locale = locale;
        }

        public override string ToString()
        {
            if (string.IsNullOrEmpty(Locale))
                return Text ?? string.Empty;
            return $"[{Locale}] {Text}";
        }

        public void Encode(BinaryEncoder encoder)
        {
            encoder.WriteByte(_encoding);
            if ((_encoding & 0x01) != 0)
                encoder.WriteString(Locale ?? "");
            if ((_encoding & 0x02) != 0)
                encoder.WriteString(Text ?? "");
        }

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

    public class DataValue
    {
        private byte _encoding;

        public Variant? Value { get; set; }
        public StatusCode? StatusCode { get; set; }
        public DateTime? SourceTimestamp { get; set; }
        public ushort? SourcePicoseconds { get; set; }
        public DateTime? ServerTimestamp { get; set; }
        public ushort? ServerPicoseconds { get; set; }

        public DataValue()
        {
            StatusCode = new StatusCode();
        }

        public DataValue(Variant? value, StatusCode? status = null)
        {
            Value = value;
            StatusCode = status ?? new StatusCode();
        }

        public DataValue(object? value, VariantType? type = null)
        {
            Value = new Variant(value, type);
            StatusCode = new StatusCode();
        }

        public override string ToString()
        {
            return $"DataValue({Value}, {StatusCode})";
        }

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

    public class ExtensionObject
    {
        public NodeId? TypeId { get; set; }
        public byte Encoding { get; set; }
        public byte[]? Body { get; set; }

        public ExtensionObject()
        {
            TypeId = new NodeId();
            Encoding = 0;
            Body = null;
        }

        public ExtensionObject(NodeId? typeId, byte[]? body)
        {
            TypeId = typeId;
            Body = body;
            Encoding = body != null ? (byte)1 : (byte)0;
        }

        public void Encode(BinaryEncoder encoder)
        {
            NodeIdCodec.Encode(encoder, TypeId);
            encoder.WriteByte(Encoding);
            if (Encoding == 1 && Body != null)
            {
                encoder.WriteByteString(Body);
            }
        }

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

    public class UaException : Exception
    {
        public uint StatusCode { get; }

        public UaException(uint statusCode) : base($"OPC UA Error: 0x{statusCode:X8}")
        {
            StatusCode = statusCode;
        }

        public UaException(uint statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}
