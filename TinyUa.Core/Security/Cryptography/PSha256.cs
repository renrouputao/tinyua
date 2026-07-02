using System.Security.Cryptography;

namespace TinyUa.Core.Security.Cryptography
{
    internal static class PSha256
    {
        internal static byte[] Derive(byte[] secret, byte[] seed, int length)
        {
            if (length <= 0)
                return Array.Empty<byte>();

            using var hmac = new HMACSHA256(secret);

            byte[] a = hmac.ComputeHash(seed);

            var result = new byte[length];
            int offset = 0;

            var input = new byte[a.Length + seed.Length];
            Buffer.BlockCopy(seed, 0, input, a.Length, seed.Length);

            while (offset < length)
            {
                Buffer.BlockCopy(a, 0, input, 0, a.Length);
                byte[] t = hmac.ComputeHash(input);

                int copy = Math.Min(t.Length, length - offset);
                Buffer.BlockCopy(t, 0, result, offset, copy);
                offset += copy;

                a = hmac.ComputeHash(a);
            }

            return result;
        }
    }
}
