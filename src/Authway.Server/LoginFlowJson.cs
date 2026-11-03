using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authway.Server;

/// <summary>The contract speaks snake_case, and leaves out what it has nothing to say about.</summary>
internal static class LoginFlowJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
