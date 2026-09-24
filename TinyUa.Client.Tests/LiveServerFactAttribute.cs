namespace TinyUa.Client.Tests;

/// <summary>Live checks are opt-in; unavailable infrastructure is reported as skipped.</summary>
public sealed class LiveServerFactAttribute : FactAttribute
{
    public static string Endpoint => Environment.GetEnvironmentVariable("TINYUA_TEST_ENDPOINT")
        ?? "opc.tcp://localhost:4840";

    public LiveServerFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("TINYUA_TEST_ENDPOINT")))
            Skip = "Set TINYUA_TEST_ENDPOINT to opt into live OPC UA tests. Reference-server coverage runs in Security.Tests.";
    }
}
