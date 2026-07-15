using System;
using System.Threading.Tasks;
using TinyUa.Core.Logging;
using TinyUa.Client.Subscriptions;

namespace TinyUa.Client
{
    public partial class UaClient
    {
        /// <summary>
        /// Start the fluent configuration chain. Use <c>.WithSecurity(...)</c>, <c>.WithUserName(...)</c>,
        /// <c>.WithAppName(...)</c>, etc., then call <c>.BuildAndRunAsync()</c> to connect.
        /// </summary>
        /// <param name="endpointUrl">OPC UA server URL, e.g. <c>opc.tcp://localhost:4840</c>.</param>
        /// <returns>A <see cref="ClientBuilder"/> for fluent configuration.</returns>
        public static ClientBuilder ConnectTo(string endpointUrl)
            => new ClientBuilder(endpointUrl);

        /// <summary>
        /// Start the fluent configuration chain from a <see cref="Uri"/>.
        /// </summary>
        public static ClientBuilder ConnectTo(Uri endpointUri)
            => new ClientBuilder(endpointUri.ToString());

        /// <summary>
        /// Fluent builder for configuring and connecting a <see cref="UaClient"/>.
        /// All <c>With*</c> methods return the builder for chaining.
        /// Call <see cref="Build"/> to create the client without connecting,
        /// or <see cref="BuildAndRunAsync"/> to create and connect immediately.
        /// </summary>
        public class ClientBuilder
        {
            private readonly string _endpointUrl;

            private readonly UaClientOptions _options = UaClientOptions.Default;
            private bool _reconnect = true;
            private ILogger? _logger;

            internal ClientBuilder(string endpointUrl) { _endpointUrl = endpointUrl; }

            /// <summary>Set per-step network timeout (socket I/O and reconnect attempts). Default 30000ms.</summary>
            /// <param name="milliseconds">Timeout in milliseconds.</param>
            public ClientBuilder WithRequestTimeout(int milliseconds) { _options.Timeout = (uint)milliseconds; return this; }

            /// <summary>Set the application name displayed in server session diagnostics. Also updates the ApplicationUri.</summary>
            public ClientBuilder WithAppName(string name) { _options.ApplicationName = name; _options.ApplicationUri = $"urn:{name}:{Guid.NewGuid()}"; return this; }

            /// <summary>Disable automatic reconnect. Equivalent to <c>WithReconnectRetries(0)</c>.</summary>
            public ClientBuilder WithoutReconnect() { _reconnect = false; return this; }

            /// <summary>Set maximum reconnect attempts. Default -1 (infinite). Set to 0 to disable.</summary>
            public ClientBuilder WithReconnectRetries(int maxRetries) { _options.ReconnectMaxRetries = maxRetries; return this; }

            /// <summary>Set the session timeout in milliseconds. Default 3600000 (1 hour).</summary>
            public ClientBuilder WithSessionTimeout(int ms) { _options.SessionTimeout = ms; return this; }

            /// <summary>Set the error handling strategy. Default <see cref="ErrorMode.Throw"/>.</summary>
            public ClientBuilder WithErrorMode(ErrorMode mode) { _options.ErrorMode = mode; return this; }

            /// <summary>
            /// Configure the bounded, ordered queue used to dispatch subscription callbacks.
            /// The default policy waits when full and therefore applies backpressure to the
            /// finite Publish window instead of growing an unbounded callback backlog.
            /// </summary>
            public ClientBuilder WithSubscriptionDispatch(Action<SubscriptionDispatchOptions> configure)
            {
                configure(_options.SubscriptionDispatch);
                return this;
            }

            /// <summary>
            /// Set the security policy by short name (e.g. <c>"Basic256Sha256"</c>, <c>"Aes128_Sha256_RsaOaep"</c>,
            /// <c>"Aes256_Sha256_RsaPss"</c>, <c>"None"</c>). Non-None policies auto-enable SignAndEncrypt mode.
            /// </summary>
            public ClientBuilder WithSecurity(string policy)
            {
                _options.Security.Policy = policy;
                if (policy != "None")
                    _options.Security.Mode = TinyUa.Core.Security.MessageSecurityMode.SignAndEncrypt;
                return this;
            }

            /// <summary>Configure security with a callback for full control over <see cref="SecurityOptions"/>.</summary>
            /// <param name="configure">Action that receives the <see cref="SecurityOptions"/> to modify.</param>
            public ClientBuilder WithSecurity(Action<SecurityOptions> configure)
            {
                configure(_options.Security);
                return this;
            }

            /// <summary>Set username/password authentication. The password is RSA-OAEP encrypted before transmission.</summary>
            /// <param name="username">The username.</param>
            /// <param name="password">The password (plaintext, will be encrypted for transmission).</param>
            public ClientBuilder WithUserName(string username, string password)
            {
                _options.Security.UserIdentity.Type = TinyUa.Core.Security.UserTokenType.UserName;
                _options.Security.UserIdentity.Username = username;
                _options.Security.UserIdentity.Password = password;
                return this;
            }

            /// <summary>Attach a custom <see cref="ILogger"/> implementation.</summary>
            public ClientBuilder WithLogger(ILogger logger) { _logger = logger; return this; }

            /// <summary>Enable console logging via a simple callback. For custom loggers, use <see cref="WithLogger"/> instead.</summary>
            /// <param name="sink">Callback receiving (LogLevel, Exception?, message).</param>
            /// <param name="minLevel">Minimum log level to record. Default <see cref="LogLevel.Debug"/>.</param>
            public ClientBuilder EnableLog(Action<LogLevel, Exception?, string> sink, LogLevel minLevel = LogLevel.Debug)
            {
                _logger = new DelegateLogger(sink, minLevel);
                return this;
            }

            /// <summary>Enable logging to a directory. Log files are auto-created and auto-rotated.</summary>
            /// <param name="directory">Directory path for log files (created if needed).</param>
            /// <param name="minLevel">Minimum log level. Default <see cref="LogLevel.Debug"/>.</param>
            /// <param name="async">Use asynchronous file writes. Default false.</param>
            public ClientBuilder EnableLogFile(string directory, LogLevel minLevel = LogLevel.Debug, bool async = false)
            {
                _logger = new FileLogger(directory, minLevel, async);
                return this;
            }

            /// <summary>Build the <see cref="UaClient"/> without connecting. Call <see cref="UaClient.RunAsync()"/> to connect later.</summary>
            public UaClient Build()
            {
                _options.ReconnectMaxRetries = _reconnect ? _options.ReconnectMaxRetries : 0;
                var client = new UaClient(_options, _logger);
                client._endpointUrl = _endpointUrl;
                return client;
            }

            /// <summary>Build the client and connect immediately. Equivalent to <c>Build()</c> followed by <c>RunAsync()</c>.</summary>
            /// <returns>A connected <see cref="UaClient"/> ready for operations.</returns>
            public async Task<UaClient> BuildAndRunAsync()
            {
                var client = Build();
                await client.RunAsync().ConfigureAwait(false);
                return client;
            }
        }
    }
}
