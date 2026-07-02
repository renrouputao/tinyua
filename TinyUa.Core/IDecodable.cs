using TinyUa.Core.Binary;

namespace TinyUa.Core
{
    public interface IDecodable<T>
    {
        static abstract T Decode(BinaryDecoder decoder);
    }
}
