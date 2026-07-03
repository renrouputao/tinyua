using TinyUa.Core.Binary;

namespace TinyUa.Core
{
    /// <summary>
    /// Defines a type that can be encoded into a <see cref="BinaryEncoder"/>.
    /// </summary>
    public interface IEncodable
    {
        /// <summary>
        /// Encodes this instance into the given <paramref name="encoder"/>.
        /// </summary>
        /// <param name="encoder">The <see cref="BinaryEncoder"/> to write data to.</param>
        void Encode(BinaryEncoder encoder);
    }
}
