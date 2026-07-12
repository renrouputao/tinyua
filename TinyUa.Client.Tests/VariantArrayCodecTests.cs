using TinyUa.Core.Binary;
using TinyUa.Core.Types;

namespace TinyUa.Client.Tests;

/// <summary>
/// Round-trip encode/decode tests for <see cref="Variant"/> array values.
/// Regression coverage for the bug where <c>new Variant(array, type)</c> ran the array
/// through <c>ConvertToTargetType</c>, throwing on numeric arrays and corrupting string
/// arrays to the literal "System.String[]". Array-valued reads (e.g. Server_NamespaceArray,
/// i=2255) were broken before this was fixed.
/// </summary>
public class VariantArrayCodecTests
{
    private static Variant RoundTrip(Variant input)
    {
        var encoder = new BinaryEncoder();
        VariantCodec.Encode(encoder, input);
        var decoder = new BinaryDecoder(encoder.ToByteArray());
        return VariantCodec.Decode(decoder);
    }

    [Fact]
    public void StringArray_RoundTrips_WithoutCorruption()
    {
        // The exact shape of Server_NamespaceArray (i=2255).
        var original = new[]
        {
            "http://opcfoundation.org/UA/",
            "urn:server:PTC.KepwareServer:UA Server",
            "Kepware Server"
        };

        var decoded = RoundTrip(new Variant(original, VariantType.String));

        Assert.True(decoded.IsArray);
        Assert.Equal(VariantType.String, decoded.VariantType);
        var arr = Assert.IsType<string[]>(decoded.Value);
        Assert.Equal(original, arr);
        // Pre-fix, decode returned a scalar string "System.String[]" (or threw). Now the
        // decoded value is a real string[] whose elements match the original.
        Assert.Equal(3, arr.Length);
    }

    [Fact]
    public void Int32Array_RoundTrips()
    {
        var original = new[] { -5, 0, 1, 42, int.MaxValue, int.MinValue };

        var decoded = RoundTrip(new Variant(original, VariantType.Int32));

        Assert.True(decoded.IsArray);
        var arr = Assert.IsType<int[]>(decoded.Value);
        Assert.Equal(original, arr);
    }

    [Fact]
    public void DoubleArray_RoundTrips()
    {
        var original = new[] { 3.14, 2.718, -1.0, 0.0 };

        var decoded = RoundTrip(new Variant(original, VariantType.Double));

        var arr = Assert.IsType<double[]>(decoded.Value);
        Assert.Equal(original, arr);
    }

    [Fact]
    public void StringArray_InferredType_RoundTrips()
    {
        // No explicit VariantType — type is guessed from the CLR array element type.
        var original = new[] { "a", "b", "c" };

        var decoded = RoundTrip(new Variant(original));

        Assert.True(decoded.IsArray);
        var arr = Assert.IsType<string[]>(decoded.Value);
        Assert.Equal(original, arr);
    }

    [Fact]
    public void EmptyArray_RoundTrips()
    {
        var decoded = RoundTrip(new Variant(Array.Empty<int>(), VariantType.Int32));

        Assert.True(decoded.IsArray);
        var arr = Assert.IsType<int[]>(decoded.Value);
        Assert.Empty(arr);
    }

    [Fact]
    public void ArrayConstruction_DoesNotThrow()
    {
        // Before the fix, constructing a Variant over a numeric array with an explicit type
        // threw InvalidCastException inside ConvertToTargetType.
        var ex = Record.Exception(() => new Variant(new[] { 1, 2, 3 }, VariantType.Int32));
        Assert.Null(ex);
    }

    [Fact]
    public void ScalarConversion_StillApplies()
    {
        // The fix must not disable scalar conversion: double -> float via explicit type.
        var v = new Variant(3.5d, VariantType.Float);
        Assert.IsType<float>(v.Value);
        Assert.Equal(3.5f, (float)v.Value!);
    }

    [Fact]
    public void ScalarString_RoundTrips()
    {
        var decoded = RoundTrip(new Variant("hello", VariantType.String));

        Assert.False(decoded.IsArray);
        Assert.Equal("hello", decoded.Value);
    }
}
