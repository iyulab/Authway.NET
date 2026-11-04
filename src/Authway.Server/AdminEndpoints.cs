using System.Security.Cryptography;
using System.Text;

namespace Authway.Server;

/// <summary>
/// The administration API (<c>/api/v1/tenants</c>, <c>/clients</c>, …), the part of the contract the
/// <c>adminKey</c> scheme guards. A call proves itself with the installation's administration key
/// (<c>Authway:Admin:ApiKey</c>) as a bearer token; with no key configured nothing is administered.
/// This server is one tenant, so the tenant every call is about is always the default one.
/// </summary>
internal static class AdminEndpoints
{
    /// <summary>The one tenant, with the id every implementation gives its default tenant.</summary>
    public static readonly Guid DefaultTenantId = new("00000000-0000-0000-0000-000000000001");

    public static void Map(IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/v1").AddEndpointFilter<AdminAuth>();
        admin.MapGet("/tenants", ListTenants);
    }

    private static IResult ListTenants() => Results.Json(new[]
    {
        new Dictionary<string, object>
        {
            ["id"] = DefaultTenantId.ToString(),
            ["name"] = "Default",
            ["slug"] = "default",
            ["active"] = true,
            ["is_system"] = false,
        },
    });
}

/// <summary>
/// Lets a call through when it carries the administration key. Refusals are the contract's:
/// <c>401 unauthorized</c> for a missing or wrong key (naming the scheme), and
/// <c>503 admin_api_not_configured</c> when this installation has no key — it fails closed.
/// </summary>
internal sealed class AdminAuth(IConfiguration configuration) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var key = configuration["Authway:Admin:ApiKey"];
        if (string.IsNullOrEmpty(key))
        {
            return Problems.Refuse(StatusCodes.Status503ServiceUnavailable, "admin_api_not_configured", "The administration API is not configured on this installation.");
        }

        var header = context.HttpContext.Request.Headers.Authorization.ToString();
        const string Scheme = "Bearer ";
        if (!header.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase) || !SameKey(header[Scheme.Length..].Trim(), key))
        {
            context.HttpContext.Response.Headers.WWWAuthenticate = "Bearer";
            return Problems.Refuse(StatusCodes.Status401Unauthorized, "unauthorized", "A valid administration key is required.");
        }

        return await next(context);
    }

    /// <summary>Compared as hashes, so that neither the content nor the length of the key shows in the time taken.</summary>
    private static bool SameKey(string offered, string key) =>
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(offered)), SHA256.HashData(Encoding.UTF8.GetBytes(key)));
}
