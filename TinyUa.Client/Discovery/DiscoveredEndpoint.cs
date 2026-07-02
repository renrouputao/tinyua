using System;
using System.Collections.Generic;
using TinyUa.Core.Security;

namespace TinyUa.Core.Client.Discovery
{
    public class DiscoveredEndpoint
    {
        public string EndpointUrl { get; set; } = "";

        public string SecurityPolicy { get; set; } = "None";

        public string SecurityPolicyUri { get; set; } = "";

        public MessageSecurityMode SecurityMode { get; set; } = MessageSecurityMode.None;

        public byte SecurityLevel { get; set; }

        public IReadOnlyList<UserTokenType> UserTokenTypes { get; set; }
            = Array.Empty<UserTokenType>();

        public bool IsSecure => SecurityPolicy != "None";

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
