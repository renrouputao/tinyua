using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace TinyUa.Core.Binary
{
    /// <summary>
    /// Writes OPC UA binary-encoded data to an internal byte buffer.
    /// All multi-byte values are written in little-endian order per the OPC UA Binary Encoding specification.
    /// </summary>
    public class BinaryEncoder : IDisposable
    {
        private byte[] _buffer;
        private int _position;

        /// <summary>
        /// Initializes a new <see cref="BinaryEncoder"/> with a default initial capacity of 256 bytes.
        /// </summary>
        public BinaryEncoder() : this(256) { }

        /// <summary>
        /// Initializes a new <see cref="BinaryEncoder"/> with the specified initial capacity.
        /// </summary>
        /// <param name="capacity">The initial buffer capacity in bytes. The actual capacity will be at least 64 bytes.</param>
        public BinaryEncoder(int capacity)
        {
            _buffer = new byte[Math.Max(capacity, 64)];
            _position = 0;
        }

        /// <summary>
        /// Returns a segment that references the written portion of the internal buffer.
        /// </summary>
        /// <returns>An <see cref="ArraySegment{T}"/> covering the bytes written so far.</returns>
        public ArraySegment<byte> GetBuffer()
        {
            return new ArraySegment<byte>(_buffer, 0, _position);
        }

        /// <summary>
        /// Creates a new byte array containing all bytes written so far.
        /// </summary>
        /// <returns>A byte array copy of the written data.</returns>
        public byte[] ToByteArray()
        {
            if (_position == 0) return Array.Empty<byte>();
            var result = new byte[_position];
            Buffer.BlockCopy(_buffer, 0, result, 0, _position);
            return result;
        }

        /// <summary>
        /// Returns the written bytes as an array. Use <see cref="ToByteArray"/> instead.
        /// </summary>
        /// <returns>A byte array copy of the written data.</returns>
        [Obsolete("Use ToByteArray() instead")]
        public byte[] ToArray() => ToByteArray();

        /// <summary>
        /// Gets the current write position (number of bytes written).
        /// </summary>
        public int Position => _position;

        /// <summary>
        /// Gets the total number of bytes written so far.
        /// </summary>
        public int Length => _position;

        /// <summary>
        /// Gets the current capacity of the internal buffer in bytes. Grows as data is written.
        /// Useful for pooling decisions — an encoder whose buffer grew very large after a one-off
        /// message can be dropped instead of retained.
        /// </summary>
        public int Capacity => _buffer.Length;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EnsureCapacity(int count)
        {
            int required = _position + count;
            if (required <= _buffer.Length) return;
            if (required < 0 || count < 0)
                throw new OutOfMemoryException("BinaryEncoder buffer size overflow");
            // Double in 64-bit space so the loop can't wrap negative and spin forever.
            long newSize = _buffer.Length;
            while (newSize < required) newSize *= 2;
            Array.Resize(ref _buffer, (int)Math.Min(newSize, Array.MaxLength));
        }

        /// <summary>
        /// Writes a <see cref="Boolean"/> as a single byte (1 for true, 0 for false).
        /// </summary>
        /// <param name="value">The boolean value to write.</param>
        public void WriteBoolean(bool value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = value ? (byte)1 : (byte)0;
        }

        /// <summary>
        /// Writes a signed byte.
        /// </summary>
        /// <param name="value">The <see cref="SByte"/> to write.</param>
        public void WriteSByte(sbyte value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = (byte)value;
        }

        /// <summary>
        /// Writes a single unsigned byte.
        /// </summary>
        /// <param name="value">The <see cref="Byte"/> to write.</param>
        public void WriteByte(byte value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = value;
        }

        /// <summary>
        /// Writes a 16-bit signed integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="Int16"/> to write.</param>
        public void WriteInt16(short value)
        {
            EnsureCapacity(2);
            BinaryPrimitives.WriteInt16LittleEndian(_buffer.AsSpan(_position), value);
            _position += 2;
        }

        /// <summary>
        /// Writes a 16-bit unsigned integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="UInt16"/> to write.</param>
        public void WriteUInt16(ushort value)
        {
            EnsureCapacity(2);
            BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_position), value);
            _position += 2;
        }

        /// <summary>
        /// Writes a 32-bit signed integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="Int32"/> to write.</param>
        public void WriteInt32(int value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteInt32LittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        /// <summary>
        /// Writes a 32-bit unsigned integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="UInt32"/> to write.</param>
        public void WriteUInt32(uint value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        /// <summary>
        /// Writes a 64-bit signed integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="Int64"/> to write.</param>
        public void WriteInt64(long value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteInt64LittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

        /// <summary>
        /// Writes a 64-bit unsigned integer (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="UInt64"/> to write.</param>
        public void WriteUInt64(ulong value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

        /// <summary>
        /// Writes a 32-bit IEEE 754 single-precision floating-point number (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="Single"/> to write.</param>
        public void WriteFloat(float value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteSingleLittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        /// <summary>
        /// Writes a 64-bit IEEE 754 double-precision floating-point number (little-endian).
        /// </summary>
        /// <param name="value">The <see cref="Double"/> to write.</param>
        public void WriteDouble(double value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteDoubleLittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

        /// <summary>
        /// Writes a length-prefixed UTF-8 string. A null value is encoded as a length of -1.
        /// </summary>
        /// <param name="value">The string to write, or null.</param>
        public void WriteString(string? value)
        {
            if (value == null)
            {
                WriteInt32(-1);
                return;
            }

            if (value.Length == 0)
            {
                WriteInt32(0);
                return;
            }

            var maxByteCount = Encoding.UTF8.GetMaxByteCount(value.Length);
            EnsureCapacity(4 + maxByteCount);

            int lengthPos = _position;
            _position += 4;

            int bytesWritten = Encoding.UTF8.GetBytes(value, _buffer.AsSpan(_position));
            _position += bytesWritten;

            BinaryPrimitives.WriteInt32LittleEndian(_buffer.AsSpan(lengthPos), bytesWritten);
        }

        /// <summary>
        /// Writes a length-prefixed byte string. A null value is encoded as a length of -1.
        /// </summary>
        /// <param name="value">The byte array to write, or null.</param>
        public void WriteByteString(byte[]? value)
        {
            if (value == null)
            {
                WriteInt32(-1);
                return;
            }

            WriteInt32(value.Length);
            if (value.Length > 0)
            {
                EnsureCapacity(value.Length);
                Buffer.BlockCopy(value, 0, _buffer, _position, value.Length);
                _position += value.Length;
            }
        }

        /// <summary>
        /// Writes a <see cref="DateTime"/> encoded as a Windows file-time (64-bit little-endian).
        /// </summary>
        /// <param name="value">The <see cref="DateTime"/> to write.</param>
        public void WriteDateTime(DateTime value)
        {
            var ticks = ToWinFileTime(value);
            WriteInt64(ticks);
        }

        /// <summary>
        /// Writes a 16-byte <see cref="Guid"/>.
        /// </summary>
        /// <param name="value">The <see cref="Guid"/> to write.</param>
        public void WriteGuid(Guid value)
        {
            EnsureCapacity(16);
            value.TryWriteBytes(_buffer.AsSpan(_position));
            _position += 16;
        }

        /// <summary>
        /// Writes raw bytes from an array at a specific offset and count.
        /// </summary>
        /// <param name="value">The source byte array.</param>
        /// <param name="offset">The zero-based offset in <paramref name="value"/> to start copying from.</param>
        /// <param name="count">The number of bytes to copy.</param>
        public void WriteBytes(byte[] value, int offset, int count)
        {
            if (count <= 0) return;
            EnsureCapacity(count);
            Buffer.BlockCopy(value, offset, _buffer, _position, count);
            _position += count;
        }

        /// <summary>
        /// Writes the entire contents of a byte array.
        /// </summary>
        /// <param name="value">The byte array to write.</param>
        public void WriteBytes(byte[] value)
        {
            if (value == null || value.Length == 0) return;
            EnsureCapacity(value.Length);
            Buffer.BlockCopy(value, 0, _buffer, _position, value.Length);
            _position += value.Length;
        }

        private static long ToWinFileTime(DateTime value)
        {
            const long epochDiff = 116444736000000000L;

            if (value == DateTime.MinValue)
                return 0;

            if (value.Kind == DateTimeKind.Local)
                value = value.ToUniversalTime();

            return value.Ticks - DateTime.UnixEpoch.Ticks + epochDiff;
        }

        /// <summary>
        /// Writes a length-prefixed array of elements, encoding each element with the supplied action.
        /// A null array is encoded as a length of -1.
        /// </summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="array">The array to write, or null.</param>
        /// <param name="writeElement">An action that encodes a single element.</param>
        public void WriteArray<T>(T[] array, Action<T> writeElement)
        {
            if (array == null)
            {
                WriteInt32(-1);
                return;
            }

            WriteInt32(array.Length);
            foreach (var item in array)
            {
                writeElement(item);
            }
        }

        /// <summary>
        /// Writes a length-prefixed array of elements, encoding each element with the supplied action that receives this encoder.
        /// A null array is encoded as a length of -1.
        /// </summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="array">The array to write, or null.</param>
        /// <param name="writeElement">An action that encodes a single element, receiving this encoder as the first argument.</param>
        public void WriteArray<T>(T[] array, Action<BinaryEncoder, T> writeElement)
        {
            if (array == null)
            {
                WriteInt32(-1);
                return;
            }

            WriteInt32(array.Length);
            foreach (var item in array)
            {
                writeElement(this, item);
            }
        }

        /// <summary>
        /// Resets the write position to 0, allowing the encoder to be reused without reallocating the internal buffer.
        /// </summary>
        public void Reset()
        {
            _position = 0;
        }

        /// <summary>
        /// Releases all resources used by the <see cref="BinaryEncoder"/>.
        /// </summary>
        public void Dispose()
        {

        }
    }
}
