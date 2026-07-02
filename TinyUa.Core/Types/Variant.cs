using System;

namespace TinyUa.Core.Types
{
    public enum VariantType : byte
    {
        Null = 0,
        Boolean = 1,
        SByte = 2,
        Byte = 3,
        Int16 = 4,
        UInt16 = 5,
        Int32 = 6,
        UInt32 = 7,
        Int64 = 8,
        UInt64 = 9,
        Float = 10,
        Double = 11,
        String = 12,
        DateTime = 13,
        Guid = 14,
        ByteString = 15,
        XmlElement = 16,
        NodeId = 17,
        ExpandedNodeId = 18,
        StatusCode = 19,
        QualifiedName = 20,
        LocalizedText = 21,
        ExtensionObject = 22,
        DataValue = 23,
        Variant = 24,
        DiagnosticInfo = 25
    }

    public class Variant
    {
        public VariantType VariantType { get; private set; }
        public object? Value { get; private set; }
        public bool IsArray { get; internal set; }
        public int[]? Dimensions { get; internal set; }

        public Variant()
        {
            VariantType = VariantType.Null;
            Value = null;
            IsArray = false;
            Dimensions = null;
        }

        public Variant(object? value, VariantType? type = null)
        {
            Value = value;
            VariantType = type ?? GuessType(value);
            IsArray = value is Array && value.GetType() != typeof(byte[]);

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

        private static VariantType GuessType(object? value)
        {
            if (value == null)
                return VariantType.Null;

            var type = value.GetType();

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

            if (type.IsArray)
            {
                var elementType = type.GetElementType();
                if (elementType == typeof(byte))
                    return VariantType.ByteString;
            }

            return VariantType.ExtensionObject;
        }

        public T GetValue<T>()
        {
            if (Value is T typedValue)
                return typedValue;

            return (T)Convert.ChangeType(Value!, typeof(T));
        }

        public override string ToString()
        {
            if (Value == null)
                return $"Variant(Null)";

            if (IsArray && Value is Array arr)
                return $"Variant([{arr.Length} elements], {VariantType})";

            return $"Variant({Value}, {VariantType})";
        }

        public static Variant Null => new Variant();
    }
}
