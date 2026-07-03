using System;
using System.Collections.Generic;
using TinyUa.Core.Security;

namespace TinyUa.Core.Client.Discovery
{
    /// <summary>
    /// Represents an OPC UA endpoint discovered from a server's GetEndpoints response.
    /// Captures the URL, security configuration, and supported user token types.
    /// </summary>
    public class DiscoveredEndpoint
    {
        /// <summary>
        /// Gets or sets the URL of the endpoint.
        /// </summary>
        public string EndpointUrl { get; set; } = "";

        /// <summary>
        /// Gets or sets the short name of the security policy (e.g. "None", "Basic256Sha256").
        /// </summary>
        public string SecurityPolicy { get; set; } = "None";

        /// <summary>
        /// Gets or sets the full URI identifying the security policy.
        /// </summary>
        public string SecurityPolicyUri { get; set; } = "";

        /// <summary>
        /// Gets or sets the message security mode used by this endpoint.
        /// </summary>
        public MessageSecurityMode SecurityMode { get; set; } = MessageSecurityMode.None;

        /// <summary>
        /// Gets or sets the server-assigned security level for this endpoint.
        /// Higher values indicate stronger security.
        /// </summary>
        public byte SecurityLevel { get; set; }

        /// <summary>
        /// Gets or sets the list of user token types supported by this endpoint.
        /// </summary>
        public IReadOnlyList<UserTokenType> UserTokenTypes { get; set; }
            = Array.Empty<UserTokenType>();

        /// <summary>
        /// Gets a value indicating whether this endpoint uses a security policy other than "None".
        /// </summary>
        public bool IsSecure => SecurityPolicy != "None";

        /// <summary>
        /// Gets a human-readable summary of the endpoint's security configuration,
        /// including the policy name, security mode, security level, and supported token types.
        /// </summary>
        public string DisplayText
        {
            get
            {
                var tokens = UserTokenTypes.Count > 0
                    ? "[" + string.Join(", ", UserTokenTypes) + "]"
                    : "[]";
                return $"{SecurityPolicy} / {SecurityMode} (lvl {SecurityLevel}) {tokens}";
            }
        }
    }
}
