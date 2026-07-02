using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace TinyUa.Core.Binary
{

    public class BinaryDecoder : IDisposable
    {
        private byte[] _data;
        private int _offset;
        private int _count;
        private int _position;

        public BinaryDecoder(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = 0;
            _count = data.Length;
            _position = 0;
        }

        public BinaryDecoder(byte[] data, int offset, int count)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = offset;
            _count = count;
            _position = 0;
        }

        public int Position => _position;
        public int Length => _count;
        public int Remaining => _count - _position;
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

        public bool ReadBoolean()
        {
            return ReadByte() != 0;
        }

        public sbyte ReadSByte()
        {
            return (sbyte)ReadByte();
        }

        public byte ReadByte()
        {
            if (_position >= _count)
                throw new InvalidOperationException("Not enough data: need 1 byte");
            return _data[_offset + _position++];
        }

        public short ReadInt16()
        {
            return BinaryPrimitives.ReadInt16LittleEndian(ReadSpan(2));
        }

        public ushort ReadUInt16()
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(ReadSpan(2));
        }

        public int ReadInt32()
        {
            return BinaryPrimitives.ReadInt32LittleEndian(ReadSpan(4));
        }

        public uint ReadUInt32()
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(ReadSpan(4));
        }

        public long ReadInt64()
        {
            return BinaryPrimitives.ReadInt64LittleEndian(ReadSpan(8));
        }

        public ulong ReadUInt64()
        {
            return BinaryPrimitives.ReadUInt64LittleEndian(ReadSpan(8));
        }

        public float ReadFloat()
        {
            return BinaryPrimitives.ReadSingleLittleEndian(ReadSpan(4));
        }

        public double ReadDouble()
        {
            return BinaryPrimitives.ReadDoubleLittleEndian(ReadSpan(8));
        }

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

        public byte[]? ReadByteString()
        {
            var length = ReadInt32();
            if (length < 0)
                return null;

            if (length == 0)
                return Array.Empty<byte>();

            return ReadBytes(length);
        }

        public DateTime ReadDateTime()
        {
            var ticks = ReadInt64();
            return FromWinFileTime(ticks);
        }

        public Guid ReadGuid()
        {
            var span = ReadSpan(16);
            return new Guid(span);
        }

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

        public T[] ReadArray<T>(BinaryDecoderDelegate<T> readElement)
        {
            return ReadArray(new Func<T>(() => readElement(this)));
        }

        public void Skip(int count)
        {
            if (_position + count > _count)
                throw new InvalidOperationException($"Cannot skip {count} bytes, only {Remaining} remaining");
            _position += count;
        }

        public byte[] GetRemainingBytes()
        {
            return ReadBytes(Remaining);
        }

        public void Reset(byte[] data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
            _offset = 0;
            _count = data.Length;
            _position = 0;
        }

        public void Dispose()
        {

        }
    }

    public delegate T BinaryDecoderDelegate<T>(BinaryDecoder decoder);
}
