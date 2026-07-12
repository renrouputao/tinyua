using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Core.Binary
{
    /// <summary>
    /// Provides binary encoding and decoding for <see cref="NodeId"/> values according to the OPC UA Binary Encoding specification.
    /// </summary>
    public static class NodeIdCodec
    {
        /// <summary>
        /// Encodes a <see cref="NodeId"/> into the given <paramref name="encoder"/>.
        /// A null node id is encoded as a two-byte NodeId with identifier 0.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        /// <param name="nodeId">The <see cref="NodeId"/> to encode, or null.</param>
        public static void Encode(BinaryEncoder encoder, NodeId? nodeId)
        {
            if (nodeId == null)
            {
                encoder.WriteByte((byte)NodeIdType.TwoByte);
                encoder.WriteByte(0);
                return;
            }

            bool hasNamespaceUri = !string.IsNullOrEmpty(nodeId.NamespaceUri);
            bool hasServerIndex = nodeId.ServerIndex > 0;

            if (!hasNamespaceUri && !hasServerIndex)
            {
                switch (nodeId.NodeIdType)
                {
                    case NodeIdType.TwoByte:
                        encoder.WriteByte((byte)NodeIdType.TwoByte);
                        encoder.WriteByte((byte)nodeId.GetNumericId());
                        return;
                    case NodeIdType.FourByte:
                        encoder.WriteByte((byte)NodeIdType.FourByte);
                        encoder.WriteByte((byte)nodeId.NamespaceIndex);
                        encoder.WriteUInt16((ushort)nodeId.GetNumericId());
                        return;
                    case NodeIdType.Numeric:
                        encoder.WriteByte((byte)NodeIdType.Numeric);
                        encoder.WriteUInt16(nodeId.NamespaceIndex);
                        encoder.WriteUInt32(nodeId.GetNumericId());
                        return;
                }
            }

            byte encodingByte = (byte)nodeId.NodeIdType;
            if (hasNamespaceUri) encodingByte |= 0x80;
            if (hasServerIndex) encodingByte |= 0x40;
            encoder.WriteByte(encodingByte);

            switch (nodeId.NodeIdType)
            {
                case NodeIdType.TwoByte:
                    encoder.WriteByte((byte)nodeId.GetNumericId());
                    break;
                case NodeIdType.FourByte:
                    encoder.WriteByte((byte)nodeId.NamespaceIndex);
                    encoder.WriteUInt16((ushort)nodeId.GetNumericId());
                    break;
                case NodeIdType.Numeric:
                    encoder.WriteUInt16(nodeId.NamespaceIndex);
                    encoder.WriteUInt32(nodeId.GetNumericId());
                    break;
                case NodeIdType.String:
                    encoder.WriteUInt16(nodeId.NamespaceIndex);
                    encoder.WriteString((string?)nodeId.Identifier ?? "");
                    break;
                case NodeIdType.ByteString:
                    encoder.WriteUInt16(nodeId.NamespaceIndex);
                    encoder.WriteByteString((byte[]?)nodeId.Identifier);
                    break;
                case NodeIdType.Guid:
                    encoder.WriteUInt16(nodeId.NamespaceIndex);
                    encoder.WriteGuid((Guid)nodeId.Identifier!);
                    break;
                default:
                    throw new UaException(0x80000000, $"Unknown NodeIdType: {nodeId.NodeIdType}");
            }

            if (hasNamespaceUri)
            {
                encoder.WriteString(nodeId.NamespaceUri ?? "");
            }

            if (hasServerIndex)
            {
                encoder.WriteUInt32(nodeId.ServerIndex);
            }
        }

        /// <summary>
        /// Decodes a <see cref="NodeId"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="NodeId"/>.</returns>
        public static NodeId Decode(BinaryDecoder decoder)
        {
            var encodingByte = decoder.ReadByte();
            var type = (NodeIdType)(encodingByte & 0x3F);

            NodeId nodeId;

            switch (type)
            {
                case NodeIdType.TwoByte:
                    nodeId = new NodeId(decoder.ReadByte());
                    break;

                case NodeIdType.FourByte:
                    var ns4 = decoder.ReadByte();
                    var id4 = decoder.ReadUInt16();
                    nodeId = new NodeId(id4, ns4);
                    break;

                case NodeIdType.Numeric:
                    var nsNum = decoder.ReadUInt16();
                    var idNum = decoder.ReadUInt32();
                    nodeId = new NodeId(idNum, nsNum);
                    break;

                case NodeIdType.String:
                    var nsStr = decoder.ReadUInt16();
                    var idStr = decoder.ReadString();
                    nodeId = new NodeId(idStr!, nsStr);
                    break;

                case NodeIdType.ByteString:
                    var nsBs = decoder.ReadUInt16();
                    var idBs = decoder.ReadByteString();
                    nodeId = new NodeId(idBs!, nsBs);
                    break;

                case NodeIdType.Guid:
                    var nsGuid = decoder.ReadUInt16();
                    var idGuid = decoder.ReadGuid();
                    nodeId = new NodeId(idGuid, nsGuid);
                    break;

                default:
                    throw new UaException(0x80000000, $"Unknown NodeIdType: {type}");
            }

            if ((encodingByte & 0x80) != 0)
            {
                nodeId.NamespaceUri = decoder.ReadString();
            }

            if ((encodingByte & 0x40) != 0)
            {
                nodeId.ServerIndex = decoder.ReadUInt32();
            }

            return nodeId;
        }
    }

    /// <summary>
    /// Provides binary encoding and decoding for <see cref="Variant"/> values according to the OPC UA Binary Encoding specification.
    /// Supports both scalar and array variants with optional multi-dimensional dimensions.
    /// </summary>
    public static class VariantCodec
    {
        /// <summary>
        /// Encodes a <see cref="Variant"/> into the given <paramref name="encoder"/>.
        /// A null variant or one with <see cref="VariantType.Null"/> is encoded as a single null byte.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        /// <param name="variant">The <see cref="Variant"/> to encode, or null.</param>
        public static void Encode(BinaryEncoder encoder, Variant? variant)
        {
            if (variant == null || variant.VariantType == VariantType.Null)
            {
                encoder.WriteByte((byte)VariantType.Null);
                return;
            }

            byte encodingByte = (byte)variant.VariantType;

            if (variant.IsArray)
            {
                encodingByte |= 0x80;
                if (variant.Dimensions != null && variant.Dimensions.Length > 0)
                {
                    encodingByte |= 0x40;
                }
            }

            encoder.WriteByte(encodingByte);

            if (variant.IsArray)
            {
                EncodeArrayValue(encoder, variant);
                if (variant.Dimensions != null && variant.Dimensions.Length > 0)
                {
                    foreach (var dim in variant.Dimensions)
                    {
                        encoder.WriteInt32(dim);
                    }
                }
            }
            else
            {
                EncodeScalarValue(encoder, variant);
            }
        }

        private static void EncodeScalarValue(BinaryEncoder encoder, Variant variant)
        {
                switch (variant.VariantType)
                {
                    case VariantType.Boolean:
                        encoder.WriteBoolean((bool)variant.Value!);
                        break;
                    case VariantType.SByte:
                        encoder.WriteSByte((sbyte)variant.Value!);
                        break;
                    case VariantType.Byte:
                        encoder.WriteByte((byte)variant.Value!);
                        break;
                    case VariantType.Int16:
                        encoder.WriteInt16((short)variant.Value!);
                        break;
                    case VariantType.UInt16:
                        encoder.WriteUInt16((ushort)variant.Value!);
                        break;
                    case VariantType.Int32:
                        encoder.WriteInt32((int)variant.Value!);
                        break;
                    case VariantType.UInt32:
                        encoder.WriteUInt32((uint)variant.Value!);
                        break;
                    case VariantType.Int64:
                        encoder.WriteInt64((long)variant.Value!);
                        break;
                    case VariantType.UInt64:
                        encoder.WriteUInt64((ulong)variant.Value!);
                        break;
                    case VariantType.Float:
                        encoder.WriteFloat((float)variant.Value!);
                        break;
                    case VariantType.Double:
                        encoder.WriteDouble((double)variant.Value!);
                        break;
                    case VariantType.String:
                        encoder.WriteString((string?)variant.Value);
                        break;
                    case VariantType.DateTime:
                        encoder.WriteDateTime((DateTime)variant.Value!);
                        break;
                    case VariantType.Guid:
                        encoder.WriteGuid((Guid)variant.Value!);
                        break;
                    case VariantType.ByteString:
                        encoder.WriteByteString((byte[]?)variant.Value);
                        break;
                    case VariantType.NodeId:
                    case VariantType.ExpandedNodeId:
                        NodeIdCodec.Encode(encoder, (NodeId)variant.Value!);
                        break;
                    case VariantType.StatusCode:
                        encoder.WriteUInt32(((StatusCode)variant.Value!).Value);
                        break;
                    case VariantType.QualifiedName:
                        ((QualifiedName)variant.Value!).Encode(encoder);
                        break;
                    case VariantType.LocalizedText:
                        ((LocalizedText)variant.Value!).Encode(encoder);
                        break;
                    case VariantType.ExtensionObject:
                        ((ExtensionObject)variant.Value!).Encode(encoder);
                        break;
                    case VariantType.DataValue:
                        ((DataValue)variant.Value!).Encode(encoder);
                        break;
                    default:
                        throw new UaException(0x80000000, $"Unsupported VariantType: {variant.VariantType}");
                }
            }

        private static void EncodeArrayValue(BinaryEncoder encoder, Variant variant)
        {
            var array = (Array)variant.Value!;
            var length = array.Length;

            encoder.WriteInt32(length);

            // Typed fast paths: avoid per-element boxing (Array.GetValue) and a temporary
            // Variant allocation per element. Guarded on the declared VariantType matching the
            // runtime element type — a mismatch (e.g. int[] declared as Int64) falls through to
            // the converting slow path below.
            switch (variant.VariantType)
            {
                case VariantType.Boolean when array is bool[] ab:
                    foreach (var v in ab) encoder.WriteBoolean(v);
                    return;
                case VariantType.SByte when array is sbyte[] asb:
                    foreach (var v in asb) encoder.WriteSByte(v);
                    return;
                case VariantType.Byte when array is byte[] aby:
                    foreach (var v in aby) encoder.WriteByte(v);
                    return;
                case VariantType.Int16 when array is short[] as16:
                    foreach (var v in as16) encoder.WriteInt16(v);
                    return;
                case VariantType.UInt16 when array is ushort[] au16:
                    foreach (var v in au16) encoder.WriteUInt16(v);
                    return;
                case VariantType.Int32 when array is int[] ai32:
                    foreach (var v in ai32) encoder.WriteInt32(v);
                    return;
                case VariantType.UInt32 when array is uint[] au32:
                    foreach (var v in au32) encoder.WriteUInt32(v);
                    return;
                case VariantType.Int64 when array is long[] ai64:
                    foreach (var v in ai64) encoder.WriteInt64(v);
                    return;
                case VariantType.UInt64 when array is ulong[] au64:
                    foreach (var v in au64) encoder.WriteUInt64(v);
                    return;
                case VariantType.Float when array is float[] af:
                    foreach (var v in af) encoder.WriteFloat(v);
                    return;
                case VariantType.Double when array is double[] ad:
                    foreach (var v in ad) encoder.WriteDouble(v);
                    return;
                case VariantType.String when array is string?[] astr:
                    foreach (var v in astr) encoder.WriteString(v);
                    return;
                case VariantType.DateTime when array is DateTime[] adt:
                    foreach (var v in adt) encoder.WriteDateTime(v);
                    return;
                case VariantType.Guid when array is Guid[] ag:
                    foreach (var v in ag) encoder.WriteGuid(v);
                    return;
                case VariantType.StatusCode when array is Types.StatusCode[] asc:
                    foreach (var v in asc) encoder.WriteUInt32(v.Value);
                    return;
            }

            for (int i = 0; i < length; i++)
            {
                var item = array.GetValue(i);
                EncodeScalarValue(encoder, new Variant(item, variant.VariantType));
            }
        }

        /// <summary>
        /// Decodes a <see cref="Variant"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="Variant"/>.</returns>
        public static Variant Decode(BinaryDecoder decoder)
        {
            var encodingByte = decoder.ReadByte();
            var type = (VariantType)(encodingByte & 0x3F);
            bool isArray = (encodingByte & 0x80) != 0;
            bool hasDimensions = (encodingByte & 0x40) != 0;

            if (type == VariantType.Null)
            {
                return Variant.Null;
            }

            object? value;

            if (isArray)
            {
                value = DecodeArrayValue(decoder, type);
            }
            else
            {
                value = DecodeScalarValue(decoder, type);
            }

            int[]? dimensions = null;
            if (hasDimensions)
            {
                var dimCount = decoder.ReadInt32();
                if (dimCount < 0 || dimCount > decoder.Remaining / 4)
                    throw new UaException(0x80000000,
                        $"Invalid variant dimension count: {dimCount}");
                dimensions = new int[dimCount];
                for (int i = 0; i < dimCount; i++)
                {
                    dimensions[i] = decoder.ReadInt32();
                }
            }

            return new Variant(value, type) { Dimensions = dimensions, IsArray = isArray };
        }

        private static object DecodeScalarValue(BinaryDecoder decoder, VariantType type)
        {
            return type switch
            {
                VariantType.Boolean => decoder.ReadBoolean(),
                VariantType.SByte => decoder.ReadSByte(),
                VariantType.Byte => decoder.ReadByte(),
                VariantType.Int16 => decoder.ReadInt16(),
                VariantType.UInt16 => decoder.ReadUInt16(),
                VariantType.Int32 => decoder.ReadInt32(),
                VariantType.UInt32 => decoder.ReadUInt32(),
                VariantType.Int64 => decoder.ReadInt64(),
                VariantType.UInt64 => decoder.ReadUInt64(),
                VariantType.Float => decoder.ReadFloat(),
                VariantType.Double => decoder.ReadDouble(),
                VariantType.String => decoder.ReadString()!,
                VariantType.DateTime => decoder.ReadDateTime(),
                VariantType.Guid => decoder.ReadGuid(),
                VariantType.ByteString => decoder.ReadByteString()!,
                VariantType.NodeId or VariantType.ExpandedNodeId => NodeIdCodec.Decode(decoder),
                VariantType.StatusCode => new StatusCode(decoder.ReadUInt32()),
                VariantType.QualifiedName => QualifiedName.Decode(decoder),
                VariantType.LocalizedText => LocalizedText.Decode(decoder),
                VariantType.ExtensionObject => ExtensionObject.Decode(decoder),
                VariantType.DataValue => DataValue.Decode(decoder),
                _ => throw new UaException(0x80000000, $"Unsupported VariantType: {type}")
            };
        }

        private static Array DecodeArrayValue(BinaryDecoder decoder, VariantType type)
        {
            var length = decoder.ReadInt32();
            if (length < 0)
                return Array.Empty<object>();

            // Guard against a malformed/hostile length prefix over-allocating: every element
            // consumes at least one byte, so a valid count cannot exceed the bytes remaining.
            if (length > decoder.Remaining)
                throw new UaException(0x80000000,
                    $"Array length {length} exceeds remaining buffer ({decoder.Remaining} bytes)");

            // Typed fast paths: avoid Array.CreateInstance + boxed SetValue per element.
            switch (type)
            {
                case VariantType.Boolean:
                { var a = new bool[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadBoolean(); return a; }
                case VariantType.SByte:
                { var a = new sbyte[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadSByte(); return a; }
                case VariantType.Byte:
                { var a = new byte[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadByte(); return a; }
                case VariantType.Int16:
                { var a = new short[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadInt16(); return a; }
                case VariantType.UInt16:
                { var a = new ushort[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadUInt16(); return a; }
                case VariantType.Int32:
                { var a = new int[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadInt32(); return a; }
                case VariantType.UInt32:
                { var a = new uint[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadUInt32(); return a; }
                case VariantType.Int64:
                { var a = new long[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadInt64(); return a; }
                case VariantType.UInt64:
                { var a = new ulong[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadUInt64(); return a; }
                case VariantType.Float:
                { var a = new float[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadFloat(); return a; }
                case VariantType.Double:
                { var a = new double[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadDouble(); return a; }
                case VariantType.String:
                { var a = new string?[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadString(); return a; }
                case VariantType.DateTime:
                { var a = new DateTime[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadDateTime(); return a; }
                case VariantType.Guid:
                { var a = new Guid[length]; for (int i = 0; i < length; i++) a[i] = decoder.ReadGuid(); return a; }
                case VariantType.StatusCode:
                { var a = new Types.StatusCode[length]; for (int i = 0; i < length; i++) a[i] = new Types.StatusCode(decoder.ReadUInt32()); return a; }
            }

            var elementType = GetElementType(type);
            var array = Array.CreateInstance(elementType, length);

            for (int i = 0; i < length; i++)
            {
                array.SetValue(DecodeScalarValue(decoder, type), i);
            }

            return array;
        }

        private static Type GetElementType(VariantType type)
        {
            return type switch
            {
                VariantType.Boolean => typeof(bool),
                VariantType.SByte => typeof(sbyte),
                VariantType.Byte => typeof(byte),
                VariantType.Int16 => typeof(short),
                VariantType.UInt16 => typeof(ushort),
                VariantType.Int32 => typeof(int),
                VariantType.UInt32 => typeof(uint),
                VariantType.Int64 => typeof(long),
                VariantType.UInt64 => typeof(ulong),
                VariantType.Float => typeof(float),
                VariantType.Double => typeof(double),
                VariantType.String => typeof(string),
                VariantType.DateTime => typeof(DateTime),
                VariantType.Guid => typeof(Guid),
                VariantType.ByteString => typeof(byte[]),
                VariantType.NodeId or VariantType.ExpandedNodeId => typeof(NodeId),
                VariantType.StatusCode => typeof(StatusCode),
                VariantType.QualifiedName => typeof(QualifiedName),
                VariantType.LocalizedText => typeof(LocalizedText),
                VariantType.ExtensionObject => typeof(ExtensionObject),
                VariantType.DataValue => typeof(DataValue),
                _ => typeof(object)
            };
        }
    }

    /// <summary>
    /// Provides binary encoding and decoding for <see cref="ExpandedNodeId"/> values, delegating to <see cref="NodeIdCodec"/>.
    /// </summary>
    public static class ExpandedNodeIdCodec
    {
        /// <summary>
        /// Encodes an <see cref="ExpandedNodeId"/> by delegating to <see cref="NodeIdCodec.Encode"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        /// <param name="nodeId">The <see cref="ExpandedNodeId"/> to encode.</param>
        public static void Encode(BinaryEncoder encoder, ExpandedNodeId nodeId)
        {
            NodeIdCodec.Encode(encoder, nodeId);
        }

        /// <summary>
        /// Decodes an <see cref="ExpandedNodeId"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="ExpandedNodeId"/>.</returns>
        public static ExpandedNodeId Decode(BinaryDecoder decoder)
        {
            var nodeId = NodeIdCodec.Decode(decoder);
            var expanded = new ExpandedNodeId();
            expanded.SetFrom(nodeId);
            return expanded;
        }
    }

    /// <summary>
    /// Provides binary encoding and decoding for <see cref="QualifiedName"/> values.
    /// </summary>
    public static class QualifiedNameCodec
    {
        /// <summary>
        /// Encodes a <see cref="QualifiedName"/> into the given <paramref name="encoder"/>.
        /// A null value is encoded as namespace index 0 with a null name.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        /// <param name="name">The <see cref="QualifiedName"/> to encode, or null.</param>
        public static void Encode(BinaryEncoder encoder, QualifiedName? name)
        {
            if (name == null)
            {
                encoder.WriteUInt16(0);
                encoder.WriteString(null);
                return;
            }
            encoder.WriteUInt16(name.NamespaceIndex);
            encoder.WriteString(name.Name);
        }

        /// <summary>
        /// Decodes a <see cref="QualifiedName"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="QualifiedName"/>.</returns>
        public static QualifiedName? Decode(BinaryDecoder decoder)
        {
            var nsIndex = decoder.ReadUInt16();
            var name = decoder.ReadString();
            return new QualifiedName(name ?? "", nsIndex);
        }
    }

    /// <summary>
    /// Provides binary encoding and decoding for <see cref="LocalizedText"/> values.
    /// Uses an encoding mask byte where bit 0 indicates locale is present and bit 1 indicates text is present.
    /// </summary>
    public static class LocalizedTextCodec
    {
        /// <summary>
        /// Encodes a <see cref="LocalizedText"/> into the given <paramref name="encoder"/>.
        /// A null value is encoded as a single zero byte.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write to.</param>
        /// <param name="text">The <see cref="LocalizedText"/> to encode, or null.</param>
        public static void Encode(BinaryEncoder encoder, LocalizedText? text)
        {
            if (text == null)
            {
                encoder.WriteByte(0);
                return;
            }
            byte encoding = 0;
            if (text.Locale != null) encoding |= 0x01;
            if (text.Text != null) encoding |= 0x02;
            encoder.WriteByte(encoding);
            if (text.Locale != null) encoder.WriteString(text.Locale);
            if (text.Text != null) encoder.WriteString(text.Text);
        }

        /// <summary>
        /// Decodes a <see cref="LocalizedText"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
        /// <returns>The decoded <see cref="LocalizedText"/>.</returns>
        public static LocalizedText? Decode(BinaryDecoder decoder)
        {
            var encoding = decoder.ReadByte();
            var text = new LocalizedText();
            if ((encoding & 0x01) != 0) text.Locale = decoder.ReadString();
            if ((encoding & 0x02) != 0) text.Text = decoder.ReadString();
            return text;
        }
    }
}
