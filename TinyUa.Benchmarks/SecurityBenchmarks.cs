using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TinyUa.Core.Security.Cryptography;

namespace TinyUa.Benchmarks;

internal static class SecurityBenchmarks
{
    public static async Task RunAsync()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("=== TinyUa Security Benchmarks ===");
        Console.WriteLine();
        Console.WriteLine("--- Crypto Primitives ---");
        Console.WriteLine();
        BenchCryptoPrimitives();
        Console.WriteLine();
        Console.WriteLine("Done.");
    }

    private static void BenchCryptoPrimitives()
    {
        const int iterations = 1000;

        using var rsaLocal = RSA.Create(2048);
        using var rsaRemote = RSA.Create(2048);
        var localCert = CreateSelfSignedCert(rsaLocal, "CN=BenchLocal");
        var remoteCert = CreateSelfSignedCert(rsaRemote, "CN=BenchRemote");

        var smallData = new byte[256];
        var medData = new byte[1024];
        var largeData = new byte[4096];
        new Random(42).NextBytes(smallData);
        new Random(43).NextBytes(medData);
        new Random(44).NextBytes(largeData);

        Console.WriteLine($"  Iterations: {iterations} (avg per op)");
        Console.WriteLine($"  Key size: RSA-2048");
        Console.WriteLine();

        Console.WriteLine($"  {"Operation",-42} {"256B",10} {"1KB",10} {"4KB",10}");
        Console.WriteLine($"  {new string('-', 42)} {new string('-', 10)} {new string('-', 10)} {new string('-', 10)}");

        var rsaOaepSha1 = RSAEncryptionPadding.OaepSHA1;
        Console.Write($"  {"RSA-2048 OAEP-SHA1 Encrypt",42}");
        BenchRsaEncrypt(rsaRemote, rsaOaepSha1, smallData, medData, largeData, iterations);

        Console.Write($"  {"RSA-2048 OAEP-SHA1 Decrypt",42}");
        BenchRsaDecrypt(rsaRemote, rsaOaepSha1, smallData, medData, largeData, iterations);

        var rsaOaepSha256 = RSAEncryptionPadding.OaepSHA256;
        Console.Write($"  {"RSA-2048 OAEP-SHA256 Encrypt",42}");
        BenchRsaEncrypt(rsaRemote, rsaOaepSha256, smallData, medData, largeData, iterations);

        Console.Write($"  {"RSA-2048 OAEP-SHA256 Decrypt",42}");
        BenchRsaDecrypt(rsaRemote, rsaOaepSha256, smallData, medData, largeData, iterations);

        var rsaPkcs1 = RSASignaturePadding.Pkcs1;
        Console.Write($"  {"RSA-2048 PKCS1-SHA256 Sign",42}");
        BenchRsaSign(rsaLocal, HashAlgorithmName.SHA256, rsaPkcs1, smallData, medData, largeData, iterations);

        Console.Write($"  {"RSA-2048 PKCS1-SHA256 Verify",42}");
        BenchRsaVerify(rsaRemote, HashAlgorithmName.SHA256, rsaPkcs1, smallData, medData, largeData, iterations);

        var rsaPss = RSASignaturePadding.Pss;
        Console.Write($"  {"RSA-2048 PSS-SHA384 Sign",42}");
        BenchRsaSign(rsaLocal, HashAlgorithmName.SHA384, rsaPss, smallData, medData, largeData, iterations);

        Console.Write($"  {"RSA-2048 PSS-SHA384 Verify",42}");
        BenchRsaVerify(rsaRemote, HashAlgorithmName.SHA384, rsaPss, smallData, medData, largeData, iterations);

        Console.WriteLine();

        Console.Write($"  {"AES-128-CBC Encrypt",42}");
        BenchAes(128, smallData, medData, largeData, iterations, encrypt: true);

        Console.Write($"  {"AES-128-CBC Decrypt",42}");
        BenchAes(128, smallData, medData, largeData, iterations, encrypt: false);

        Console.Write($"  {"AES-256-CBC Encrypt",42}");
        BenchAes(256, smallData, medData, largeData, iterations, encrypt: true);

        Console.Write($"  {"AES-256-CBC Decrypt",42}");
        BenchAes(256, smallData, medData, largeData, iterations, encrypt: false);

        Console.WriteLine();

        Console.Write($"  {"HMAC-SHA256 Sign",42}");
        BenchHmac(smallData, medData, largeData, iterations);

        Console.Write($"  {"P_SHA256 Derive (80 bytes)",42}");
        BenchPSha256(iterations);

        Console.WriteLine();
        Console.Write($"  {"TinyUa RsaCryptography Encrypt (1KB)",42}");
        BenchTinyUaRsa(localCert, remoteCert, medData, iterations, rsaOaepSha1, HashAlgorithmName.SHA256, rsaPkcs1, 42);

        Console.Write($"  {"TinyUa RsaCryptography Sign (1KB)",42}");
        BenchTinyUaRsaSign(localCert, remoteCert, medData, iterations, rsaOaepSha1, HashAlgorithmName.SHA256, rsaPkcs1, 42);

        Console.Write($"  {"TinyUa AesCryptography Encrypt (1KB)",42}");
        BenchTinyUaAes(medData, iterations, 16);

        Console.Write($"  {"TinyUa AesCryptography Encrypt (1KB, AES-256)",42}");
        BenchTinyUaAes(medData, iterations, 32);

        localCert.Dispose();
        remoteCert.Dispose();
    }

    private static void BenchRsaEncrypt(RSA rsa, RSAEncryptionPadding padding,
        byte[] small, byte[] med, byte[] large, int iters)
    {
        var blockSize = rsa.KeySize / 8 - (padding == RSAEncryptionPadding.OaepSHA1 ? 42 : 66);
        var block = new byte[Math.Min(blockSize, 214)];
        Console.Write($"  {BenchUs(() => rsa.Encrypt(block, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.Encrypt(block, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.Encrypt(block, padding), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchRsaDecrypt(RSA rsa, RSAEncryptionPadding padding,
        byte[] small, byte[] med, byte[] large, int iters)
    {
        var blockSize = rsa.KeySize / 8 - (padding == RSAEncryptionPadding.OaepSHA1 ? 42 : 66);
        var block = new byte[Math.Min(blockSize, 214)];
        var encrypted = rsa.Encrypt(block, padding);
        Console.Write($"  {BenchUs(() => rsa.Decrypt(encrypted, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.Decrypt(encrypted, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.Decrypt(encrypted, padding), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchRsaSign(RSA rsa, HashAlgorithmName hash, RSASignaturePadding padding,
        byte[] small, byte[] med, byte[] large, int iters)
    {
        Console.Write($"  {BenchUs(() => rsa.SignData(small, hash, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.SignData(med, hash, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.SignData(large, hash, padding), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchRsaVerify(RSA rsa, HashAlgorithmName hash, RSASignaturePadding padding,
        byte[] small, byte[] med, byte[] large, int iters)
    {
        using var signer = RSA.Create(rsa.KeySize);
        var sigS = signer.SignData(small, hash, padding);
        var sigM = signer.SignData(med, hash, padding);
        var sigL = signer.SignData(large, hash, padding);
        var pubParams = signer.ExportParameters(false);
        rsa.ImportParameters(pubParams);
        Console.Write($"  {BenchUs(() => rsa.VerifyData(small, sigS, hash, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.VerifyData(med, sigM, hash, padding), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => rsa.VerifyData(large, sigL, hash, padding), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchAes(int keyBits, byte[] small, byte[] med, byte[] large, int iters, bool encrypt)
    {
        using var aes = Aes.Create();
        aes.KeySize = keyBits;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.GenerateKey();
        aes.GenerateIV();

        var smallP = PadToBlock(small, aes.BlockSize / 8);
        var medP = PadToBlock(med, aes.BlockSize / 8);
        var largeP = PadToBlock(large, aes.BlockSize / 8);

        if (encrypt)
        {
            Console.Write($"  {BenchUs(() => aes.EncryptCbc(smallP, aes.IV), iters),8:F1} us");
            Console.Write($"  {BenchUs(() => aes.EncryptCbc(medP, aes.IV), iters),8:F1} us");
            Console.Write($"  {BenchUs(() => aes.EncryptCbc(largeP, aes.IV), iters),8:F1} us");
        }
        else
        {
            var eS = aes.EncryptCbc(smallP, aes.IV);
            var eM = aes.EncryptCbc(medP, aes.IV);
            var eL = aes.EncryptCbc(largeP, aes.IV);
            Console.Write($"  {BenchUs(() => aes.DecryptCbc(eS, aes.IV), iters),8:F1} us");
            Console.Write($"  {BenchUs(() => aes.DecryptCbc(eM, aes.IV), iters),8:F1} us");
            Console.Write($"  {BenchUs(() => aes.DecryptCbc(eL, aes.IV), iters),8:F1} us");
        }
        Console.WriteLine();
    }

    private static void BenchHmac(byte[] small, byte[] med, byte[] large, int iters)
    {
        var key = new byte[32];
        using var hmac = new HMACSHA256(key);
        Console.Write($"  {BenchUs(() => hmac.ComputeHash(small), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => hmac.ComputeHash(med), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => hmac.ComputeHash(large), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchPSha256(int iters)
    {
        var secret = new byte[32];
        var seed = new byte[32];
        new Random(42).NextBytes(secret);
        new Random(43).NextBytes(seed);
        Console.Write($"  {BenchUs(() => PSha256.Derive(secret, seed, 80), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => PSha256.Derive(secret, seed, 80), iters),8:F1} us");
        Console.Write($"  {BenchUs(() => PSha256.Derive(secret, seed, 80), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchTinyUaRsa(X509Certificate2 localCert, X509Certificate2 remoteCert,
        byte[] data, int iters, RSAEncryptionPadding encPadding, HashAlgorithmName sigHash,
        RSASignaturePadding sigPadding, int oaepOverhead)
    {
        using var localKey = localCert.GetRSAPrivateKey()!;
        using var remoteKey = remoteCert.GetRSAPublicKey()!;
        var rsa = new RsaCryptography(localKey, remoteKey, encPadding, sigHash, sigPadding, oaepOverhead);

        Console.Write($"  {BenchUs(() => rsa.Encrypt(data), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchTinyUaRsaSign(X509Certificate2 localCert, X509Certificate2 remoteCert,
        byte[] data, int iters, RSAEncryptionPadding encPadding, HashAlgorithmName sigHash,
        RSASignaturePadding sigPadding, int oaepOverhead)
    {
        using var localKey = localCert.GetRSAPrivateKey()!;
        using var remoteKey = remoteCert.GetRSAPublicKey()!;
        var rsa = new RsaCryptography(localKey, remoteKey, encPadding, sigHash, sigPadding, oaepOverhead);

        Console.Write($"  {BenchUs(() => rsa.Sign(data), iters),8:F1} us");
        Console.WriteLine();
    }

    private static void BenchTinyUaAes(byte[] data, int iters, int encKeySize)
    {
        var aes = new AesCryptography(
            signatureKeySize: 32,
            encryptionKeySize: encKeySize,
            blockSize: 16,
            mode: TinyUa.Core.Security.MessageSecurityMode.SignAndEncrypt);

        var secret = new byte[32];
        var seed = new byte[32];
        new Random(42).NextBytes(secret);
        new Random(43).NextBytes(seed);
        aes.MakeLocalKeys(secret, seed);
        aes.MakeRemoteKeys(seed, secret);

        var padded = PadToBlock(data, 16);

        Console.Write($"  {BenchUs(() => aes.Encrypt(padded), iters),8:F1} us");
        Console.WriteLine();
    }

    private static double BenchUs(Action op, int iters)
    {
        op();
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iters; i++) op();
        sw.Stop();
        return sw.Elapsed.TotalMicroseconds / iters;
    }

    private static byte[] PadToBlock(byte[] data, int blockSize)
    {
        int remainder = data.Length % blockSize;
        if (remainder == 0) return data;
        var padded = new byte[data.Length + (blockSize - remainder)];
        Buffer.BlockCopy(data, 0, padded, 0, data.Length);
        return padded;
    }

    private static X509Certificate2 CreateSelfSignedCert(RSA rsa, string subjectName)
    {
        var req = new CertificateRequest(
            subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.NonRepudiation,
                true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }
}
