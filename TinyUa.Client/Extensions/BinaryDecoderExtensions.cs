using System;
using TinyUa.Core.Binary;
using TinyUa.Core.Types;
using TinyUa.Core.Client.Services;

namespace TinyUa.Core.Client
{
    public static class BinaryDecoderExtensions
    {
        private const uint ServiceFaultTypeId = 397;

        public static uint ReadTypeIdValue(this BinaryDecoder decoder)
        {
            var encodingByte = decoder.ReadByte();
            var type = (NodeIdType)(encodingByte & 0x3F);

            switch (type)
            {
                case NodeIdType.TwoByte:
                    return decoder.ReadByte();
                case NodeIdType.FourByte:
                    decoder.ReadByte();
                    return decoder.ReadUInt16();
                case NodeIdType.Numeric:
                    decoder.ReadUInt16();
                    return decoder.ReadUInt32();
                case NodeIdType.String:
                    decoder.ReadUInt16();
                    decoder.ReadString();
                    return 0;
                case NodeIdType.Guid:
                    decoder.ReadUInt16();
                    decoder.Skip(16);
                    return 0;
                case NodeIdType.ByteString:
                    decoder.ReadUInt16();
                    decoder.ReadByteString();
                    return 0;
                default:
                    return 0;
            }

        }

        public static void CheckServiceFault(this BinaryDecoder decoder)
        {
            var typeIdValue = decoder.ReadTypeIdValue();

            if (typeIdValue == ServiceFaultTypeId)
            {
                var header = ResponseHeader.Decode(decoder);
                throw new UaException(header.ServiceResult.Value, $"ServiceFault: 0x{header.ServiceResult.Value:X8}");
            }
        }

        public static void SkipDiagnosticInfos(this BinaryDecoder decoder)
        {
            if (decoder.Remaining < 4)
                return;

            var count = decoder.ReadInt32();
            for (int i = 0; i < count; i++)
            {
                var encoding = decoder.ReadByte();
                if ((encoding & 0x01) != 0) decoder.ReadInt32();
                if ((encoding & 0x02) != 0) decoder.ReadInt32();
                if ((encoding & 0x04) != 0) decoder.ReadString();
                if ((encoding & 0x08) != 0) decoder.ReadString();
                if ((encoding & 0x10) != 0) decoder.ReadByte();
                if ((encoding & 0x20) != 0) decoder.ReadInt32();
                if ((encoding & 0x40) != 0) decoder.ReadInt32();
            }
        }
    }
}
