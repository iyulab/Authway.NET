using System.Text.Json;
using OpenIddict.Abstractions;

namespace Authway.Server;

/// <summary>What the server asks of an application it has registered.</summary>
internal static class Clients
{
    /// <summary>
    /// Whether the application is on. An administrator turns one off (<c>active: false</c>): it signs no one in and
    /// issues nothing until it is turned on again. One that was never turned off has no setting and is on.
    /// </summary>
    public static async Task<bool> IsOnAsync(this IOpenIddictApplicationManager applications, object application)
    {
        var properties = await applications.GetPropertiesAsync(application);
        return !(properties.TryGetValue("active", out var active) && active.ValueKind == JsonValueKind.False);
    }
}
