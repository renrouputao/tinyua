using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace TinyUa.Core.Binary
{

    public class BinaryEncoder : IDisposable
    {
        private byte[] _buffer;
        private int _position;

        public BinaryEncoder() : this(256) { }

        public BinaryEncoder(int capacity)
        {
            _buffer = new byte[Math.Max(capacity, 64)];
            _position = 0;
        }

        public ArraySegment<byte> GetBuffer()
        {
            return new ArraySegment<byte>(_buffer, 0, _position);
        }

        public byte[] ToByteArray()
        {
            if (_position == 0) return Array.Empty<byte>();
            var result = new byte[_position];
            Buffer.BlockCopy(_buffer, 0, result, 0, _position);
            return result;
        }

        [Obsolete("Use ToByteArray() instead")]
        public byte[] ToArray() => ToByteArray();

        public int Position => _position;
        public int Length => _position;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EnsureCapacity(int count)
        {
            if (_position + count <= _buffer.Length) return;
            int newSize = _buffer.Length;
            while (newSize < _position + count) newSize *= 2;
            Array.Resize(ref _buffer, newSize);
        }

        public void WriteBoolean(bool value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = value ? (byte)1 : (byte)0;
        }

        public void WriteSByte(sbyte value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = (byte)value;
        }

        public void WriteByte(byte value)
        {
            EnsureCapacity(1);
            _buffer[_position++] = value;
        }

        public void WriteInt16(short value)
        {
            EnsureCapacity(2);
            BinaryPrimitives.WriteInt16LittleEndian(_buffer.AsSpan(_position), value);
            _position += 2;
        }

        public void WriteUInt16(ushort value)
        {
            EnsureCapacity(2);
            BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_position), value);
            _position += 2;
        }

        public void WriteInt32(int value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteInt32LittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        public void WriteUInt32(uint value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        public void WriteInt64(long value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteInt64LittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

        public void WriteUInt64(ulong value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

        public void WriteFloat(float value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteSingleLittleEndian(_buffer.AsSpan(_position), value);
            _position += 4;
        }

        public void WriteDouble(double value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteDoubleLittleEndian(_buffer.AsSpan(_position), value);
            _position += 8;
        }

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

        public void WriteDateTime(DateTime value)
        {
            var ticks = ToWinFileTime(value);
            WriteInt64(ticks);
        }

        public void WriteGuid(Guid value)
        {
            EnsureCapacity(16);
            value.TryWriteBytes(_buffer.AsSpan(_position));
            _position += 16;
        }

        public void WriteBytes(byte[] value, int offset, int count)
        {
            if (count <= 0) return;
            EnsureCapacity(count);
            Buffer.BlockCopy(value, offset, _buffer, _position, count);
            _position += count;
        }

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

        public void Reset()
        {
            _position = 0;
        }

        public void Dispose()
        {

        }
    }
}
