using System;
using TinyUa.Core.Binary;

namespace TinyUa.Core.Types
{
    /// <summary>
    /// Defines the encoding format for an OPC UA NodeId.
    /// </summary>
    public enum NodeIdType : byte
    {
        /// <summary>Two-byte numeric identifier with namespace index 0.</summary>
        TwoByte = 0,
        /// <summary>Four-byte numeric identifier with a single-byte namespace index.</summary>
        FourByte = 1,
        /// <summary>Full 32-bit numeric identifier with a 16-bit namespace index.</summary>
        Numeric = 2,
        /// <summary>String-based identifier.</summary>
        String = 3,
        /// <summary>GUID-based identifier.</summary>
        Guid = 4,
        /// <summary>Opaque byte-string identifier.</summary>
        ByteString = 5
    }

    /// <summary>
    /// Represents an OPC UA NodeId, a qualified identifier for a node in the address space.
    /// Supports numeric, string, GUID, byte-string, and compact two-byte / four-byte representations.
    /// </summary>
    public class NodeId : IEquatable<NodeId?>, IComparable<NodeId?>
    {
        // Numeric identifiers (the common case) live in _numeric so equality, hashing, and
        // comparison never box. _reference holds string / byte[] identifiers, or the Guid boxed
        // once at construction. Exactly one of the two is meaningful, selected by NodeIdType.
        private ulong _numeric;
        private object? _reference;

        /// <summary>
        /// Gets the encoding format of this NodeId.
        /// </summary>
        public NodeIdType NodeIdType { get; private set; }

        /// <summary>
        /// Gets the namespace index for this NodeId.
        /// </summary>
        public ushort NamespaceIndex { get; private set; }

        /// <summary>
        /// Gets the identifier value. The runtime type depends on <see cref="NodeIdType"/>.
        /// Numeric identifiers are boxed on access; use <see cref="GetNumericId"/> to avoid that.
        /// </summary>
        public object? Identifier => NodeIdType switch
        {
            NodeIdType.TwoByte => (byte)_numeric,
            NodeIdType.FourByte => (ushort)_numeric,
            NodeIdType.Numeric => (uint)_numeric,
            _ => _reference
        };

        /// <summary>
        /// Gets or sets the resolved namespace URI. Can be set externally via namespace table lookup.
        /// </summary>
        public string? NamespaceUri { get; internal set; }

        /// <summary>
        /// Gets or sets the server index, used in expanded NodeIds to reference a remote server.
        /// </summary>
        public uint ServerIndex { get; internal set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeId"/> class as a null / zero-value NodeId
        /// (TwoByte encoding, identifier 0, namespace index 0).
        /// </summary>
        public NodeId()
        {
            NodeIdType = NodeIdType.TwoByte;
            NamespaceIndex = 0;
            _numeric = 0;
            NamespaceUri = null;
            ServerIndex = 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeId"/> class with a numeric identifier.
        /// Automatically chooses TwoByte, FourByte, or Numeric encoding based on value ranges.
        /// </summary>
        /// <param name="identifier">The numeric identifier.</param>
        /// <param name="namespaceIndex">The namespace index (default 0).</param>
        public NodeId(uint identifier, ushort namespaceIndex = 0)
        {
            if (namespaceIndex == 0 && identifier <= byte.MaxValue)
            {
                NodeIdType = NodeIdType.TwoByte;
                NamespaceIndex = 0;
            }
            else if (namespaceIndex <= byte.MaxValue && identifier <= ushort.MaxValue)
            {
                NodeIdType = NodeIdType.FourByte;
                NamespaceIndex = namespaceIndex;
            }
            else
            {
                NodeIdType = NodeIdType.Numeric;
                NamespaceIndex = namespaceIndex;
            }
            _numeric = identifier;
            NamespaceUri = null;
            ServerIndex = 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeId"/> class with a string identifier.
        /// </summary>
        /// <param name="identifier">The string identifier. Must not be null.</param>
        /// <param name="namespaceIndex">The namespace index (default 0).</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="identifier"/> is null.</exception>
        public NodeId(string identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.String;
            NamespaceIndex = namespaceIndex;
            _reference = identifier ?? throw new ArgumentNullException(nameof(identifier));
            NamespaceUri = null;
            ServerIndex = 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeId"/> class with a GUID identifier.
        /// </summary>
        /// <param name="identifier">The GUID identifier.</param>
        /// <param name="namespaceIndex">The namespace index (default 0).</param>
        public NodeId(Guid identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.Guid;
            NamespaceIndex = namespaceIndex;
            _reference = identifier;
            NamespaceUri = null;
            ServerIndex = 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NodeId"/> class with a byte-string identifier.
        /// </summary>
        /// <param name="identifier">The byte-string identifier. Must not be null.</param>
        /// <param name="namespaceIndex">The namespace index (default 0).</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="identifier"/> is null.</exception>
        public NodeId(byte[] identifier, ushort namespaceIndex = 0)
        {
            NodeIdType = NodeIdType.ByteString;
            NamespaceIndex = namespaceIndex;
            _reference = identifier ?? throw new ArgumentNullException(nameof(identifier));
            NamespaceUri = null;
            ServerIndex = 0;
        }

        /// <summary>
        /// Parses a NodeId from its string representation (e.g. "ns=2;s=MyVariable" or "i=2258").
        /// </summary>
        /// <param name="value">The string to parse. If null or empty, returns a null NodeId.</param>
        /// <returns>A new <see cref="NodeId"/> parsed from the string.</returns>
        /// <exception cref="FormatException">Thrown when the string format is invalid.</exception>
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

        /// <summary>
        /// Gets the numeric identifier value. Only valid for TwoByte, FourByte, and Numeric NodeIds.
        /// </summary>
        /// <returns>The numeric identifier as a <see cref="uint"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the NodeId is not a numeric type.</exception>
        public uint GetNumericId()
        {
            return NodeIdType switch
            {
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => (uint)_numeric,
                _ => throw new InvalidOperationException("NodeId is not numeric")
            };
        }

        /// <summary>
        /// Determines whether this NodeId represents a null / zero-value identifier.
        /// </summary>
        /// <returns><c>true</c> if the NodeId is null (zero; empty; etc.) in the context of its type; otherwise <c>false</c>.</returns>
        public bool IsNull()
        {
            if (NamespaceIndex != 0)
                return false;

            return NodeIdType switch
            {
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => _numeric == 0,
                NodeIdType.String => string.IsNullOrEmpty((string?)_reference),
                NodeIdType.Guid => (Guid)_reference! == Guid.Empty,
                NodeIdType.ByteString => ((byte[]?)_reference)?.Length == 0,
                _ => true
            };
        }

        /// <summary>
        /// Returns the canonical string representation of this NodeId (e.g. "ns=2;i=2258").
        /// </summary>
        /// <returns>A string representing the NodeId.</returns>
        public override string ToString()
        {
            var parts = new System.Collections.Generic.List<string>();

            if (NamespaceIndex != 0)
                parts.Add($"ns={NamespaceIndex}");

            var idStr = NodeIdType switch
            {
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => $"i={_numeric}",
                NodeIdType.String => $"s={_reference}",
                NodeIdType.Guid => $"g={((Guid)_reference!):D}",
                NodeIdType.ByteString => $"b={Convert.ToBase64String((byte[])_reference!)}",
                _ => $"i=0"
            };
            parts.Add(idStr);

            if (ServerIndex > 0)
                parts.Add($"srv={ServerIndex}");

            if (!string.IsNullOrEmpty(NamespaceUri))
                parts.Add($"nsu={NamespaceUri}");

            return string.Join(";", parts);
        }

        /// <summary>
        /// Determines whether the current <see cref="NodeId"/> is equal to another <see cref="NodeId"/>.
        /// </summary>
        /// <param name="other">The other NodeId to compare with, or null.</param>
        /// <returns><c>true</c> if the namespace index, type, and identifier are all equal; otherwise <c>false</c>.</returns>
        public bool Equals(NodeId? other)
        {
            if (other is null)
                return false;

            if (NamespaceIndex != other.NamespaceIndex || NodeIdType != other.NodeIdType)
                return false;

            return NodeIdType switch
            {
                // Numeric identifiers compare without boxing — this is the hot path for
                // monitored-item routing and dictionary lookups.
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => _numeric == other._numeric,
                _ => Equals(_reference, other._reference)
            };
        }

        /// <summary>
        /// Determines whether the current <see cref="NodeId"/> is equal to another object.
        /// </summary>
        /// <param name="obj">The object to compare with.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is a <see cref="NodeId"/> and equal to this instance; otherwise <c>false</c>.</returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as NodeId);
        }

        /// <summary>
        /// Returns a hash code for this NodeId.
        /// </summary>
        /// <returns>A hash code combining the namespace index, type, and identifier.</returns>
        public override int GetHashCode()
        {
            int identifierHash = NodeIdType switch
            {
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => _numeric.GetHashCode(),
                _ => _reference?.GetHashCode() ?? 0
            };
            return HashCode.Combine(NamespaceIndex, NodeIdType, identifierHash);
        }

        /// <summary>
        /// Compares the current NodeId with another NodeId.
        /// </summary>
        /// <param name="other">The other NodeId to compare with, or null.</param>
        /// <returns>A value indicating the relative sort order.</returns>
        public int CompareTo(NodeId? other)
        {
            if (other is null)
                return 1;

            int result = NamespaceIndex.CompareTo(other.NamespaceIndex);
            if (result != 0)
                return result;

            return NodeIdType switch
            {
                NodeIdType.TwoByte or NodeIdType.FourByte or NodeIdType.Numeric => _numeric.CompareTo(other._numeric),
                NodeIdType.String => string.Compare((string?)_reference, (string?)other._reference, StringComparison.Ordinal),
                NodeIdType.Guid => ((Guid)_reference!).CompareTo((Guid)other._reference!),
                _ => 0
            };
        }

        internal void SetFrom(NodeId other)
        {
            NodeIdType = other.NodeIdType;
            NamespaceIndex = other.NamespaceIndex;
            _numeric = other._numeric;
            _reference = other._reference;
            NamespaceUri = other.NamespaceUri;
            ServerIndex = other.ServerIndex;
        }

        /// <summary>
        /// Determines whether two <see cref="NodeId"/> instances are equal.
        /// </summary>
        /// <param name="left">The first NodeId to compare.</param>
        /// <param name="right">The second NodeId to compare.</param>
        /// <returns><c>true</c> if both are null or both are equal; otherwise <c>false</c>.</returns>
        public static bool operator ==(NodeId? left, NodeId? right)
        {
            if (left is null)
                return right is null;
            return left.Equals(right);
        }

        /// <summary>
        /// Determines whether two <see cref="NodeId"/> instances are not equal.
        /// </summary>
        /// <param name="left">The first NodeId to compare.</param>
        /// <param name="right">The second NodeId to compare.</param>
        /// <returns><c>true</c> if the NodeIds are not equal; otherwise <c>false</c>.</returns>
        public static bool operator !=(NodeId? left, NodeId? right)
        {
            return !(left == right);
        }

        /// <summary>
        /// Converts a NodeId string representation to a <see cref="NodeId"/> instance.
        /// </summary>
        /// <param name="nodeIdString">A string in canonical NodeId format (e.g. "i=2258").</param>
        public static implicit operator NodeId(string nodeIdString)
            => Parse(nodeIdString);

        /// <summary>
        /// Converts a <see cref="uint"/> to a <see cref="NodeId"/> with namespace index 0.
        /// The appropriate encoding (TwoByte, FourByte, or Numeric) is chosen automatically.
        /// </summary>
        /// <param name="numericId">The numeric identifier.</param>
        public static implicit operator NodeId(uint numericId)
            => new NodeId(numericId, 0);
    }

    /// <summary>
    /// Represents an OPC UA ExpandedNodeId, which extends <see cref="NodeId"/> with server index
    /// and optional namespace URI for absolute addressing across servers.
    /// </summary>
    public class ExpandedNodeId : NodeId
    {
        /// <inheritdoc/>
        public ExpandedNodeId() : base() { }
        /// <inheritdoc/>
        public ExpandedNodeId(uint identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        /// <inheritdoc/>
        public ExpandedNodeId(string identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        /// <inheritdoc/>
        public ExpandedNodeId(Guid identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
        /// <inheritdoc/>
        public ExpandedNodeId(byte[] identifier, ushort namespaceIndex = 0) : base(identifier, namespaceIndex) { }
    }
}
