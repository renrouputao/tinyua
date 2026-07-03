using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace TinyUa.Core.Binary
{
    /// <summary>
    /// Reads OPC UA binary-encoded data from a byte buffer.
    /// All multi-byte values are read in little-endian order per the OPC UA Binary Encoding specification.
    /// </summary>
    public class BinaryDecoder : IDisposable
    {
        private byte[] _data;
        private int _offset;
        private int _count;
        private int _position;

        /// <summary>
        /// Initializes a new <see cref="BinaryDecoder"/> that reads from the given byte array.
        /// </summary>
        /// <param name="data">The byte array containing the encoded data.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
        public BinaryDecoder(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = 0;
            _count = data.Length;
            _position = 0;
        }

        /// <summary>
        /// Initializes a new <see cref="BinaryDecoder"/> that reads from a sub-range of the given byte array.
        /// </summary>
        /// <param name="data">The byte array containing the encoded data.</param>
        /// <param name="offset">The zero-based offset in <paramref name="data"/> at which reading begins.</param>
        /// <param name="count">The number of bytes available to read.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
        public BinaryDecoder(byte[] data, int offset, int count)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = offset;
            _count = count;
            _position = 0;
        }

        /// <summary>
        /// Gets the current read position within the buffer.
        /// </summary>
        public int Position => _position;

        /// <summary>
        /// Gets the total number of bytes available in the buffer.
        /// </summary>
        public int Length => _count;

        /// <summary>
        /// Gets the number of bytes remaining to be read.
        /// </summary>
        public int Remaining => _count - _position;

        /// <summary>
        /// Gets whether there are more bytes available to read.
        /// </summary>
        public bool HasMore => Remaining > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ReadOnlySpan<byte> ReadSpan(int count)
        {
            if (_position + count > _count)
                throw new InvalidOperationException($"Not enough data: need {count}, have {Remaining}");
            var span = _data.AsSpan(_offset + _position, count);
            _position += count;
            return span;
        }

        /// <summary>
        /// Reads a <see cref="Boolean"/> value (1 byte, non-zero is true).
        /// </summary>
        /// <returns>The decoded boolean.</returns>
        public bool ReadBoolean()
        {
            return ReadByte() != 0;
        }

        /// <summary>
        /// Reads a signed byte.
        /// </summary>
        /// <returns>The decoded <see cref="SByte"/>.</returns>
        public sbyte ReadSByte()
        {
            return (sbyte)ReadByte();
        }

        /// <summary>
        /// Reads a single unsigned byte.
        /// </summary>
        /// <returns>The decoded <see cref="Byte"/>.</returns>
        public byte ReadByte()
        {
            if (_position >= _count)
                throw new InvalidOperationException("Not enough data: need 1 byte");
            return _data[_offset + _position++];
        }

        /// <summary>
        /// Reads a 16-bit signed integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="Int16"/>.</returns>
        public short ReadInt16()
        {
            return BinaryPrimitives.ReadInt16LittleEndian(ReadSpan(2));
        }

        /// <summary>
        /// Reads a 16-bit unsigned integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="UInt16"/>.</returns>
        public ushort ReadUInt16()
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(ReadSpan(2));
        }

        /// <summary>
        /// Reads a 32-bit signed integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="Int32"/>.</returns>
        public int ReadInt32()
        {
            return BinaryPrimitives.ReadInt32LittleEndian(ReadSpan(4));
        }

        /// <summary>
        /// Reads a 32-bit unsigned integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="UInt32"/>.</returns>
        public uint ReadUInt32()
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(ReadSpan(4));
        }

        /// <summary>
        /// Reads a 64-bit signed integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="Int64"/>.</returns>
        public long ReadInt64()
        {
            return BinaryPrimitives.ReadInt64LittleEndian(ReadSpan(8));
        }

        /// <summary>
        /// Reads a 64-bit unsigned integer (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="UInt64"/>.</returns>
        public ulong ReadUInt64()
        {
            return BinaryPrimitives.ReadUInt64LittleEndian(ReadSpan(8));
        }

        /// <summary>
        /// Reads a 32-bit IEEE 754 single-precision floating-point number (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="Single"/>.</returns>
        public float ReadFloat()
        {
            return BinaryPrimitives.ReadSingleLittleEndian(ReadSpan(4));
        }

        /// <summary>
        /// Reads a 64-bit IEEE 754 double-precision floating-point number (little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="Double"/>.</returns>
        public double ReadDouble()
        {
            return BinaryPrimitives.ReadDoubleLittleEndian(ReadSpan(8));
        }

        /// <summary>
        /// Reads a length-prefixed UTF-8 string. A negative length indicates null.
        /// </summary>
        /// <returns>The decoded string, or null if the length-prefix was negative.</returns>
        public string? ReadString()
        {
            var length = ReadInt32();
            if (length < 0)
                return null;

            if (length == 0)
                return string.Empty;

            var bytes = ReadBytes(length);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Reads a length-prefixed byte string (opaque binary data). A negative length indicates null.
        /// </summary>
        /// <returns>The decoded byte array, or null if the length-prefix was negative.</returns>
        public byte[]? ReadByteString()
        {
            var length = ReadInt32();
            if (length < 0)
                return null;

            if (length == 0)
                return Array.Empty<byte>();

            return ReadBytes(length);
        }

        /// <summary>
        /// Reads a <see cref="DateTime"/> encoded as a Windows file-time (64-bit little-endian).
        /// </summary>
        /// <returns>The decoded <see cref="DateTime"/>.</returns>
        public DateTime ReadDateTime()
        {
            var ticks = ReadInt64();
            return FromWinFileTime(ticks);
        }

        /// <summary>
        /// Reads a 16-byte <see cref="Guid"/>.
        /// </summary>
        /// <returns>The decoded <see cref="Guid"/>.</returns>
        public Guid ReadGuid()
        {
            var span = ReadSpan(16);
            return new Guid(span);
        }

        /// <summary>
        /// Reads a raw sequence of bytes of the specified length.
        /// </summary>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>A byte array containing the bytes read.</returns>
        public byte[] ReadBytes(int count)
        {
            if (count <= 0) return Array.Empty<byte>();
            if (_position + count > _count)
                throw new InvalidOperationException($"Not enough data: need {count}, have {Remaining}");
            var result = new byte[count];
            Buffer.BlockCopy(_data, _offset + _position, result, 0, count);
            _position += count;
            return result;
        }

        private static DateTime FromWinFileTime(long ticks)
        {
            if (ticks == 0)
                return DateTime.MinValue;

            if (ticks == Int64.MaxValue)
                return DateTime.MaxValue;

            return DateTime.FromFileTimeUtc(ticks);
        }

        /// <summary>
        /// Reads a length-prefixed array of elements, decoding each element with the supplied factory.
        /// </summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="readElement">A factory delegate that produces one element per call.</param>
        /// <returns>An array of decoded elements, or an empty array if length is zero or negative.</returns>
        public T[] ReadArray<T>(Func<T> readElement)
        {
            var length = ReadInt32();
            if (length <= 0)
                return Array.Empty<T>();

            var result = new T[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = readElement();
            }
            return result;
        }

        /// <summary>
        /// Reads a length-prefixed array of elements, decoding each element with the supplied delegate that receives this decoder.
        /// </summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="readElement">A delegate that reads one element from this decoder and returns it.</param>
        /// <returns>An array of decoded elements, or an empty array if length is zero or negative.</returns>
        public T[] ReadArray<T>(BinaryDecoderDelegate<T> readElement)
        {
            return ReadArray(new Func<T>(() => readElement(this)));
        }

        /// <summary>
        /// Advances the read position by the specified number of bytes without reading them.
        /// </summary>
        /// <param name="count">The number of bytes to skip.</param>
        /// <exception cref="InvalidOperationException">Thrown when there are fewer than <paramref name="count"/> bytes remaining.</exception>
        public void Skip(int count)
        {
            if (_position + count > _count)
                throw new InvalidOperationException($"Cannot skip {count} bytes, only {Remaining} remaining");
            _position += count;
        }

        /// <summary>
        /// Reads all remaining bytes from the buffer.
        /// </summary>
        /// <returns>A byte array containing all remaining bytes.</returns>
        public byte[] GetRemainingBytes()
        {
            return ReadBytes(Remaining);
        }

        /// <summary>
        /// Resets this decoder to read from a new byte array, starting at position 0.
        /// </summary>
        /// <param name="data">The new byte array to read from.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
        public void Reset(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = 0;
            _count = data.Length;
            _position = 0;
        }

        /// <summary>
        /// Releases all resources used by the <see cref="BinaryDecoder"/>.
        /// </summary>
        public void Dispose()
        {

        }
    }

    /// <summary>
    /// Represents a method that reads a value of type <typeparamref name="T"/> from a <see cref="BinaryDecoder"/>.
    /// </summary>
    /// <typeparam name="T">The type of the decoded value.</typeparam>
    /// <param name="decoder">The <see cref="BinaryDecoder"/> to read from.</param>
    /// <returns>The decoded value.</returns>
    public delegate T BinaryDecoderDelegate<T>(BinaryDecoder decoder);
}
