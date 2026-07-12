using TinyUa.Client.Services;
using TinyUa.Core.Security;

namespace TinyUa.Client.Security
{
    /// <summary>
    /// Builds the <see cref="UserIdentityToken"/> for ActivateSession from the configured
    /// identity options and the CreateSession response (server nonce / certificate).
    /// </summary>
    internal static class UserIdentityFactory
    {
        internal static UserIdentityToken Build(
            UserIdentityOptions identityOptions,
            CreateSessionResponse createResponse,
            SecurityPolicy policy,
            string? userTokenPolicyId)
        {
            if (identityOptions.Type == UserTokenType.UserName)
            {
                return UserIdentityToken.CreateUserName(
                    identityOptions.Username ?? "",
                    identityOptions.Password ?? "",
                    userTokenPolicyId,
                    createResponse.ServerNonce,
                    createResponse.ServerCertificate,
                    policy.Uri);
            }

            if (identityOptions.Type == UserTokenType.Certificate)
            {
                return new UserIdentityToken
                {
                    TokenType = UserTokenType.Certificate,
                    PolicyId = userTokenPolicyId,
                    IssuedId = policy.SenderCertificate,
                    SecurityPolicyUri = policy.Uri
                };
            }

            return UserIdentityToken.Anonymous();
        }
    }
}
