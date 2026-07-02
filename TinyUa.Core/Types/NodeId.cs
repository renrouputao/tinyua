using System;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    public enum NodeIdType : byte
    {
        TwoByte = 0,
        FourByte = 1,
        Numeric = 2,
        String = 3,
        Guid = 4,
        ByteString = 5
    }

    public class NodeId : IEquatable<NodeId?>, IComparable<NodeId?>
    {
        public NodeIdType NodeIdType { get; private set; }
        public ushort NamespaceIndex { get; private set; }
        public object? Identifier { get; private set; }

        public string? NamespaceUri { get; internal set; }

        public uint ServerIndex { get; internal set; }

        public NodeId()
        {
            NodeIdType = NodeIdType.TwoByte;
            NamespaceIndex = 0;
            Identifier = (byte)0;
            NamespaceUri = null;
            ServerIndex = 0;
        }

        public NodeId(uint identifier, ushort namespaceIndex = 0)
        {
            if (namespaceIndex == 0 && identifier <= byte.MaxValue)
            {
                NodeIdType = NodeIdType.TwoByte;
                NamespaceIndex = 0;
                Identifier = (byte)identifier;
            }
            else if (namespaceIndex <= byte.MaxValue && identifier <= ushort.MaxValue)
            {
                NodeIdType = NodeIdType.FourByte;
                NamespaceIndex = namespaceIndex;
                Identifier = (ushort)identifier;
            }
            else
            {
                NodeIdType = NodeIdType.Numeric;
                NamespaceIndex = namespaceIndex;
                Identifier = identifier;
            }
            NamespaceUri = null;
            ServerIndex = 0;
        }

        public NodeId(string identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.String;
            NamespaceIndex = namespaceIndex;
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            NamespaceUri = null;
            ServerIndex = 0;
        }

        public NodeId(Guid identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.Guid;
            NamespaceIndex = namespaceIndex;
            Identifier = identifier;
            NamespaceUri = null;
            ServerIndex = 0;
        }

        public NodeId(byte[] identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.ByteString;
            NamespaceIndex = namespaceIndex;
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
            NamespaceUri = null;
            ServerIndex = 0;
        }

        public static NodeId Parse(string value)
        {
            if (string.IsNullOrEmpty(value))
                return new NodeId();

            ushort ns = 0;
            string? identifier = null;
            NodeIdType type = NodeIdType.Numeric;

            var parts = value.Split(';');
            foreach (var part in parts)
            {
                if (string.IsNullOrWhiteSpace(part))
                    continue;

                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2)
                    continue;

                var key = kv[0].Trim();
                var val = kv[1].Trim();

                switch (key)
                {
                    case "ns":
                        ns = ushort.Parse(val);
                        break;
                    case "i":
                        type = NodeIdType.Numeric;
                        identifier = val;
                        break;
                    case "s":
                        type = NodeIdType.String;
                        identifier = val;
                        break;
                    case "g":
                        type = NodeIdType.Guid;
                        identifier = val;
                        break;
                    case "b":
                        type = NodeIdType.ByteString;
                        identifier = val;
                        break;
                }
            }

            if (identifier == null)
                throw new FormatException("Invalid NodeId format: missing identifier");

            return type switch
            {
                NodeIdType.Numeric => new NodeId(uint.Parse(identifier), ns),
                NodeIdType.String => new NodeId(identifier, ns),
                NodeIdType.Guid => new NodeId(Guid.Parse(identifier), ns),
                NodeIdType.ByteString => new NodeId(Convert.FromBase64String(identifier), ns),
                _ => throw new FormatException($"Unsupported NodeIdType: {type}")
            };
        }

        public uint GetNumericId()
        {
            return NodeIdType switch
            {
                NodeIdType.TwoByte => (byte)Identifier!,
                NodeIdType.FourByte => (ushort)Identifier!,
                NodeIdType.Numeric => (uint)Identifier!,
                _ => throw new InvalidOperationException("NodeId is not numeric")
            };
        }

        public bool IsNull()
        {
            if (NamespaceIndex != 0)
                return false;

            return NodeIdType switch
            {
                NodeIdType.TwoByte => (byte)Identifier! == 0,
                NodeIdType.FourByte => (ushort)Identifier! == 0,
                NodeIdType.Numeric => (uint)Identifier! == 0,
                NodeIdType.String => string.IsNullOrEmpty((string?)Identifier),
                NodeIdType.Guid => (Guid)Identifier! == Guid.Empty,
                NodeIdType.ByteString => ((byte[]?)Identifier)?.Length == 0,
                _ => true
            };
        }

        public override string ToString()
        {
            var parts = new System.Collections.Generic.List<string>();

            if (NamespaceIndex != 0)
                parts.Add($"ns={NamespaceIndex}");

            var idStr = NodeIdType switch
            {
                NodeIdType.TwoByte => $"i={(byte)Identifier!}",
                NodeIdType.FourByte => $"i={(ushort)Identifier!}",
                NodeIdType.Numeric => $"i={(uint)Identifier!}",
                NodeIdType.String => $"s={Identifier}",
                NodeIdType.Guid => $"g={((Guid)Identifier!):D}",
                NodeIdType.ByteString => $"b={Convert.ToBase64String((byte[])Identifier!)}",
                _ => $"i=0"
            };
            parts.Add(idStr);

            if (ServerIndex > 0)
                parts.Add($"srv={ServerIndex}");

            if (!string.IsNullOrEmpty(NamespaceUri))
                parts.Add($"nsu={NamespaceUri}");

            return string.Join(";", parts);
        }

        public bool Equals(NodeId? other)
        {
            if (other is null)
                return false;

            return NamespaceIndex == other.NamespaceIndex &&
                   NodeIdType == other.NodeIdType &&
                   Equals(Identifier, other.Identifier);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as NodeId);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(NamespaceIndex, NodeIdType, Identifier);
        }

        public int CompareTo(NodeId? other)
        {
            if (other is null)
                return 1;

            int result = NamespaceIndex.CompareTo(other.NamespaceIndex);
            if (result != 0)
                return result;

            return NodeIdType switch
            {
                NodeIdType.TwoByte => ((byte)Identifier!).CompareTo((byte)other.Identifier!),
                NodeIdType.FourByte => ((ushort)Identifier!).CompareTo((ushort)other.Identifier!),
                NodeIdType.Numeric => ((uint)Identifier!).CompareTo((uint)other.Identifier!),
                NodeIdType.String => string.Compare((string?)Identifier, (string?)other.Identifier, StringComparison.Ordinal),
                NodeIdType.Guid => ((Guid)Identifier!).CompareTo((Guid)other.Identifier!),
                _ => 0
            };
        }

        internal void SetFrom(NodeId other)
        {
            NodeIdType = other.NodeIdType;
            NamespaceIndex = other.NamespaceIndex;
            Identifier = other.Identifier;
            NamespaceUri = other.NamespaceUri;
            ServerIndex = other.ServerIndex;
        }

        public static bool operator ==(NodeId? left, NodeId? right)
        {
            if (left is null)
                return right is null;
            return left.Equals(right);
        }

        public static bool operator !=(NodeId? left, NodeId? right)
        {
            return !(left == right);
        }

        public static implicit operator NodeId(string nodeIdString)
            => Parse(nodeIdString);

        public static implicit operator NodeId(uint numericId)
            => new NodeId(numericId, 0);
    }

    public class ExpandedNodeId : NodeId
    {
        public ExpandedNodeId() : base() { }
        public ExpandedNodeId(uint identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        public ExpandedNodeId(string identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        public ExpandedNodeId(Guid identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        public ExpandedNodeId(byte[] identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
    }
}
