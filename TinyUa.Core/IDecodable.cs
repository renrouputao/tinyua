using TinyUa.Core.Binary;

namespace TinyUa.Core
{
    /// <summary>
    /// Defines a type that can be decoded from a <see cref="BinaryDecoder"/>.
    /// </summary>
    /// <typeparam name="T">The concrete type being decoded.</typeparam>
    public interface IDecodable<T>
    {
        /// <summary>
        /// Decodes an instance of <typeparamref name="T"/> from the given <paramref name="decoder"/>.
        /// </summary>
        /// <param name="decoder">The <see cref="BinaryDecoder"/> to read data from.</param>
        /// <returns>A new instance of <typeparamref name="T"/> populated from the decoder.</returns>
        static abstract T Decode(BinaryDecoder decoder);
    }
}
