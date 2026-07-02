using TinyUa.Core.Binary;

namespace TinyUa.Core
{
    public interface IEncodable
    {
        void Encode(BinaryEncoder encoder);
    }
}
