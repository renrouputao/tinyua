using System;

namespace TinyUa.Core.Types
{
    /// <summary>
    /// Enumerates the OPC UA built-in data types that a <see cref="Variant"/> can hold.
    /// </summary>
    public enum VariantType : byte
    {
        /// <summary>A null / empty value.</summary>
        Null = 0,
        /// <summary>A Boolean value.</summary>
        Boolean = 1,
        /// <summary>A signed 8-bit integer.</summary>
        SByte = 2,
        /// <summary>An unsigned 8-bit integer.</summary>
        Byte = 3,
        /// <summary>A signed 16-bit integer.</summary>
        Int16 = 4,
        /// <summary>An unsigned 16-bit integer.</summary>
        UInt16 = 5,
        /// <summary>A signed 32-bit integer.</summary>
        Int32 = 6,
        /// <summary>An unsigned 32-bit integer.</summary>
        UInt32 = 7,
        /// <summary>A signed 64-bit integer.</summary>
        Int64 = 8,
        /// <summary>An unsigned 64-bit integer.</summary>
        UInt64 = 9,
        /// <summary>An IEEE 754 single-precision float.</summary>
        Float = 10,
        /// <summary>An IEEE 754 double-precision float.</summary>
        Double = 11,
        /// <summary>A UTF-8 string.</summary>
        String = 12,
        /// <summary>A date/time value.</summary>
        DateTime = 13,
        /// <summary>A 128-bit GUID.</summary>
        Guid = 14,
        /// <summary>An opaque byte string.</summary>
        ByteString = 15,
        /// <summary>An XML element.</summary>
        XmlElement = 16,
        /// <summary>A <see cref="NodeId"/> value.</summary>
        NodeId = 17,
        /// <summary>An <see cref="ExpandedNodeId"/> value.</summary>
        ExpandedNodeId = 18,
        /// <summary>A <see cref="StatusCode"/> value.</summary>
        StatusCode = 19,
        /// <summary>A <see cref="QualifiedName"/> value.</summary>
        QualifiedName = 20,
        /// <summary>A <see cref="LocalizedText"/> value.</summary>
        LocalizedText = 21,
        /// <summary>An <see cref="ExtensionObject"/> value.</summary>
        ExtensionObject = 22,
        /// <summary>A <see cref="DataValue"/> value.</summary>
        DataValue = 23,
        /// <summary>A nested <see cref="Variant"/> value.</summary>
        Variant = 24,
        /// <summary>A diagnostic info value.</summary>
        DiagnosticInfo = 25
    }

    /// <summary>
    /// Represents an OPC UA Variant, a union-like type that can hold any of the
    /// OPC UA built-in data types together with optional array dimensions.
    /// </summary>
    public class Variant
    {
        /// <summary>
        /// Gets the OPC UA type of the value held by this variant.
        /// </summary>
        public VariantType VariantType { get; private set; }

        /// <summary>
        /// Gets the underlying value. May be null. Interpret according to <see cref="VariantType"/>.
        /// </summary>
        public object? Value { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the variant holds an array (excluding byte arrays,
        /// which are treated as <see cref="VariantType.ByteString"/>).
        /// </summary>
        public bool IsArray { get; internal set; }

        /// <summary>
        /// Gets the dimensions of a multi-dimensional array, or null for a flat array or scalar value.
        /// </summary>
        public int[]? Dimensions { get; internal set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Variant"/> class with a null value.
        /// </summary>
        public Variant()
        {
            VariantType = VariantType.Null;
            Value = null;
            IsArray = false;
            Dimensions = null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Variant"/> class with the specified value.
        /// The variant type is auto-detected from the CLR type unless explicitly provided.
        /// </summary>
        /// <param name="value">The value to wrap. May be null.</param>
        /// <param name="type">Optional explicit OPC UA type. If null, the type is guessed from the CLR type.</param>
        public Variant(object? value, VariantType? type = null)
        {
            // Only convert scalar values to the target CLR type. Arrays (other than byte[],
            // which is a ByteString scalar) are not IConvertible — running them through
            // ConvertToTargetType throws (numeric arrays) or corrupts them to "System.T[]"
            // (string arrays). Their elements already carry the correct type from the decoder.
            bool isArrayValue = value is Array && value.GetType() != typeof(byte[]);
            if (type != null && value != null && !isArrayValue)
                value = ConvertToTargetType(value, type.Value);

            Value = value;
            VariantType = type ?? GuessType(value);
            IsArray = isArrayValue;

            if (IsArray && value is Array arr)
            {
                var dims = new int[arr.Rank];
                for (int i = 0; i < arr.Rank; i++)
                {
                    dims[i] = arr.GetLength(i);
                }
                Dimensions = dims.Length > 1 ? dims : null;
            }
        }

        private static object ConvertToTargetType(object value, VariantType targetType)
        {
            return targetType switch
            {
                VariantType.Boolean => Convert.ToBoolean(value),
                VariantType.SByte => Convert.ToSByte(value),
                VariantType.Byte => Convert.ToByte(value),
                VariantType.Int16 => Convert.ToInt16(value),
                VariantType.UInt16 => Convert.ToUInt16(value),
                VariantType.Int32 => Convert.ToInt32(value),
                VariantType.UInt32 => Convert.ToUInt32(value),
                VariantType.Int64 => Convert.ToInt64(value),
                VariantType.UInt64 => Convert.ToUInt64(value),
                VariantType.Float => Convert.ToSingle(value),
                VariantType.Double => Convert.ToDouble(value),
                VariantType.String => Convert.ToString(value)!,
                VariantType.DateTime => Convert.ToDateTime(value),
                _ => value   // complex types (NodeId, etc.) are already the correct CLR type
            };
        }

        /// <summary>
        /// Guesses the OPC UA variant type from a CLR value.
        /// </summary>
        /// <param name="value">The CLR value to inspect.</param>
        /// <returns>The best-matching <see cref="VariantType"/>.</returns>
        private static VariantType GuessType(object? value)
        {
            if (value == null)
                return VariantType.Null;

            var type = value.GetType();

            // Arrays (except byte[], which is the ByteString scalar) are guessed from their
            // element type — otherwise a string[]/int[] would fall through to ExtensionObject
            // and mis-encode. The IsArray flag drives the array-vs-scalar encode path separately.
            if (type.IsArray && type != typeof(byte[]))
            {
                var elementType = type.GetElementType();
                return elementType != null
                    ? GuessScalarType(elementType)
                    : VariantType.ExtensionObject;
            }

            return GuessScalarType(type);
        }

        private static VariantType GuessScalarType(Type type)
        {
            if (type == typeof(bool))
                return VariantType.Boolean;
            if (type == typeof(sbyte))
                return VariantType.SByte;
            if (type == typeof(byte))
                return VariantType.Byte;
            if (type == typeof(short))
                return VariantType.Int16;
            if (type == typeof(ushort))
                return VariantType.UInt16;
            if (type == typeof(int))
                return VariantType.Int32;
            if (type == typeof(uint))
                return VariantType.UInt32;
            if (type == typeof(long))
                return VariantType.Int64;
            if (type == typeof(ulong))
                return VariantType.UInt64;
            if (type == typeof(float))
                return VariantType.Float;
            if (type == typeof(double))
                return VariantType.Double;
            if (type == typeof(string))
                return VariantType.String;
            if (type == typeof(DateTime))
                return VariantType.DateTime;
            if (type == typeof(Guid))
                return VariantType.Guid;
            if (type == typeof(byte[]))
                return VariantType.ByteString;
            if (type == typeof(NodeId) || type.IsSubclassOf(typeof(NodeId)))
                return VariantType.NodeId;
            if (type == typeof(StatusCode))
                return VariantType.StatusCode;
            if (type == typeof(QualifiedName))
                return VariantType.QualifiedName;
            if (type == typeof(LocalizedText))
                return VariantType.LocalizedText;
            if (type == typeof(ExtensionObject))
                return VariantType.ExtensionObject;
            if (type == typeof(DataValue))
                return VariantType.DataValue;
            if (type == typeof(Variant))
                return VariantType.Variant;

            return VariantType.ExtensionObject;
        }

        /// <summary>
        /// Gets the value cast to type <typeparamref name="T"/>. Uses <see cref="Convert.ChangeType"/>
        /// if a direct cast is not possible.
        /// </summary>
        /// <typeparam name="T">The target CLR type.</typeparam>
        /// <returns>The value cast to <typeparamref name="T"/>.</returns>
        public T GetValue<T>()
        {
            if (Value is T typedValue)
                return typedValue;

            return (T)Convert.ChangeType(Value!, typeof(T));
        }

        /// <summary>
        /// Returns a human-readable string describing this variant.
        /// </summary>
        /// <returns>A string in the form "Variant(value, type)" or "Variant([N elements], type)" for arrays.</returns>
        public override string ToString()
        {
            if (Value == null)
                return $"Variant(Null)";

            if (IsArray && Value is Array arr)
                return $"Variant([{arr.Length} elements], {VariantType})";

            return $"Variant({Value}, {VariantType})";
        }

        /// <summary>
        /// Gets a null variant singleton.
        /// </summary>
        public static Variant Null => new Variant();
    }
}
