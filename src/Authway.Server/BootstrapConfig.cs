namespace Authway.Server;

/// <summary>
/// <c>GET /.well-known/authway-config</c>: the one document an application or an SDK needs before anything
/// else — where the issuer is, where the API is, and where the sign-in screens are (emailed links point
/// there). One server answers for all three, so unless an installation says the screens are elsewhere
/// (<c>Authway:Ui:BaseUrl</c>) they are on the address the question was asked at.
/// </summary>
internal static class BootstrapConfig
{
    internal static readonly string Version = typeof(BootstrapConfig).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public static void Map(IEndpointRouteBuilder app) => app.MapGet("/.well-known/authway-config", (HttpContext context, IConfiguration configuration) =>
    {
        var origin = Origin(context);
        return Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = origin,
            ["api_url"] = origin,
            ["auth_ui"] = UiAddress(context, configuration),
            ["version"] = Version,
        });
    });

    /// <summary>The address the request was made at, without a path.</summary>
    public static string Origin(HttpContext context) => $"{context.Request.Scheme}://{context.Request.Host}";

    /// <summary>The sign-in screens' address, without a trailing slash.</summary>
    public static string UiAddress(HttpContext context, IConfiguration configuration) =>
        (configuration["Authway:Ui:BaseUrl"] ?? Origin(context)).TrimEnd('/');
}
