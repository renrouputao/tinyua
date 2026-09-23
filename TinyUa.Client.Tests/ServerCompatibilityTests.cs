using TinyUa.Client.Security;
using TinyUa.Client.Services;
using TinyUa.Core;
using TinyUa.Core.Binary;
using TinyUa.Core.Security;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

public class ServerCompatibilityTests
{
    [Fact]
    public void AnonymousIdentity_UsesPolicyIdAdvertisedByCreateSession()
    {
        using var connection = new TinyUa.Client.Connection.UaConnection();
        var policy = connection.SecurityPolicy;
        var response = new CreateSessionResponse
        {
            ServerEndpoints = new[]
            {
                new EndpointDescription
                {
                    SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None", SecurityMode = MessageSecurityMode.None,
                    UserIdentityTokens = new[]
                    {
                        new UserTokenPolicy { TokenType = UserTokenType.UserName, PolicyId = "user-policy" },
                        new UserTokenPolicy { TokenType = UserTokenType.Anonymous, PolicyId = "device-anonymous-policy" }
                    }
                }
            }
        };
        var token = UserIdentityFactory.Build(new UserIdentityOptions(), response, policy, null);
        var encoder = new BinaryEncoder();
        new ActivateSessionParameters { UserIdentity = token }.Encode(encoder);
        var decoder = new BinaryDecoder(encoder.ToByteArray());
        SignatureData.Decode(decoder);
        Assert.Equal(-1, decoder.ReadInt32());
        Assert.Equal(1, decoder.ReadInt32());
        decoder.ReadString();
        Assert.Equal(321u, NodeIdCodec.Decode(decoder).GetNumericId());
        Assert.Equal(1, decoder.ReadByte());
        var body = new BinaryDecoder(decoder.ReadByteString()!);
        Assert.Equal("device-anonymous-policy", body.ReadString());
    }

    [Fact]
    public void ServiceFault_WithDiagnosticStrings_PreservesOriginalStatus()
    {
        var encoder = new BinaryEncoder();
        NodeIdCodec.Encode(encoder, new NodeId(397u));
        encoder.WriteDateTime(DateTime.UtcNow);
        encoder.WriteUInt32(42);
        encoder.WriteUInt32(0x80200000); // BadIdentityTokenInvalid
        WriteDiagnostics(encoder);
        encoder.WriteInt32(2);
        encoder.WriteString("en-US");
        encoder.WriteString("Identity policy does not match the endpoint");
        NodeIdCodec.Encode(encoder, new NodeId());
        encoder.WriteByte(0);
        var decoder = new BinaryDecoder(encoder.ToByteArray());
        var error = Assert.Throws<UaException>(() => decoder.CheckServiceFault());
        Assert.Contains("80200000", error.Message);
        Assert.Contains("Unexpected identity policy", error.Message);
        Assert.Equal(0, decoder.Remaining);
    }

    [Fact]
    public void DiagnosticArray_WithNestedDiagnostic_DoesNotConsumeFollowingData()
    {
        var encoder = new BinaryEncoder();
        encoder.WriteInt32(1);
        WriteDiagnostics(encoder);
        encoder.WriteUInt32(0x12345678);
        var decoder = new BinaryDecoder(encoder.ToByteArray());
        decoder.SkipDiagnosticInfos();
        Assert.Equal(0x12345678u, decoder.ReadUInt32());
        Assert.Equal(0, decoder.Remaining);
    }

    private static void WriteDiagnostics(BinaryEncoder encoder)
    {
        encoder.WriteByte(0x7f);
        encoder.WriteInt32(0); // SymbolicId
        encoder.WriteInt32(0); // NamespaceUri
        encoder.WriteInt32(0); // Locale (string table index, NOT a String)
        encoder.WriteInt32(1); // LocalizedText (string table index)
        encoder.WriteString("Unexpected identity policy"); // AdditionalInfo
        encoder.WriteUInt32(0x80200000); // InnerStatusCode
        encoder.WriteByte(0x10); // InnerDiagnosticInfo
        encoder.WriteString("PolicyId must match the advertised token policy");
    }
}
