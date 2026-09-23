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
            string? userTokenPolicyId,
            string? endpointUrl = null)
        {
            // CreateSession includes the endpoint's token policies even for a None channel,
            // where certificate discovery was not needed. PolicyId is required for anonymous
            // identities too, and token encryption can differ from the channel policy.
            var endpoints = createResponse.ServerEndpoints?
                .Where(e => e.SecurityPolicyUri == policy.Uri && e.SecurityMode == policy.SecurityMode)
                .OrderByDescending(e => string.Equals(e.EndpointUrl, endpointUrl, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var tokenPolicy = endpoints?
                .SelectMany(e => e.UserIdentityTokens ?? Array.Empty<UserTokenPolicy>())
                .FirstOrDefault(t => t.TokenType == identityOptions.Type &&
                    (userTokenPolicyId == null || t.PolicyId == userTokenPolicyId));
            if (endpoints is { Length: > 0 } && tokenPolicy == null)
                throw new InvalidOperationException($"Server endpoint does not advertise a matching {identityOptions.Type} user token policy.");
            userTokenPolicyId = tokenPolicy?.PolicyId ?? userTokenPolicyId;
            var tokenSecurityPolicy = string.IsNullOrEmpty(tokenPolicy?.SecurityPolicyUri)
                ? policy.Uri : tokenPolicy.SecurityPolicyUri;

            if (identityOptions.Type == UserTokenType.UserName)
            {
                if (SecurityPolicyFactory.IsSecurePolicy(tokenSecurityPolicy) &&
                    (createResponse.ServerNonce is not { Length: > 0 } ||
                     createResponse.ServerCertificate is not { Length: > 0 }))
                    throw new InvalidOperationException("Server nonce and certificate are required to encrypt the user identity token.");
                return UserIdentityToken.CreateUserName(
                    identityOptions.Username ?? "",
                    identityOptions.Password ?? "",
                    userTokenPolicyId,
                    createResponse.ServerNonce,
                    createResponse.ServerCertificate,
                    tokenSecurityPolicy);
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

            var anonymous = UserIdentityToken.Anonymous();
            anonymous.PolicyId = userTokenPolicyId;
            return anonymous;
        }
    }
}
