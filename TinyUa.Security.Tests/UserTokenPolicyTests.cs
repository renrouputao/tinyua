using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TinyUa.Client;
using TinyUa.Client.Security;
using TinyUa.Client.Services;
using TinyUa.Core.Security;

namespace TinyUa.Security.Tests;

public class UserTokenPolicyTests
{
    [Fact]
    public void NoneChannel_EncryptsPasswordUsingAdvertisedTokenPolicy()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=TokenTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var nonce = RandomNumberGenerator.GetBytes(32);
        var response = Response("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        response.ServerCertificate = certificate.RawData;
        response.ServerNonce = nonce;
        var token = UserIdentityFactory.Build(new UserIdentityOptions
        {
            Type = UserTokenType.UserName, Username = "test", Password = "test-password"
        }, response, new NoneSecurityPolicy(), null);

        Assert.Equal("device-user-policy", token.PolicyId);
        Assert.Equal("http://www.w3.org/2001/04/xmlenc#rsa-oaep", token.EncryptionAlgorithm);
        var plain = rsa.Decrypt(token.Password!, RSAEncryptionPadding.OaepSHA1);
        Assert.Equal(plain.Length - 4, BinaryPrimitives.ReadInt32LittleEndian(plain));
        Assert.Equal(Encoding.UTF8.GetBytes("test-password").Concat(nonce).ToArray(), plain[4..]);
    }

    [Fact]
    public void SecureUserToken_MissingCertificate_DoesNotFallBackToPlaintext()
    {
        Assert.Throws<InvalidOperationException>(() => UserIdentityFactory.Build(new UserIdentityOptions
        {
            Type = UserTokenType.UserName, Username = "test", Password = "test-password"
        }, Response("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"), new NoneSecurityPolicy(), null));
    }

    [Fact]
    public void EndpointWithoutAnonymousPolicy_IsRejectedBeforeActivation()
    {
        Assert.Throws<InvalidOperationException>(() => UserIdentityFactory.Build(new UserIdentityOptions(),
            Response("http://opcfoundation.org/UA/SecurityPolicy#None"), new NoneSecurityPolicy(), null));
    }

    private static CreateSessionResponse Response(string tokenPolicy) => new()
    {
        ServerEndpoints = new[]
        {
            new EndpointDescription
            {
                SecurityMode = MessageSecurityMode.None,
                SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None",
                UserIdentityTokens = new[]
                {
                    new UserTokenPolicy { TokenType = UserTokenType.UserName, PolicyId = "device-user-policy", SecurityPolicyUri = tokenPolicy }
                }
            }
        }
    };
}
