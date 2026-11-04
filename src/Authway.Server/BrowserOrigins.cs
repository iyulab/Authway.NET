using Microsoft.Extensions.Primitives;

namespace Authway.Server;

/// <summary>
/// Which pages may call this server from a browser. An application's pages run on their own origin, and the
/// origin it registers on its client (<c>allowed_origins</c>) is what lets them call the routes a person calls
/// with their own token. No credential but that token is ever sent from there, so no answer allows cookies.
/// <list type="bullet">
/// <item>What describes the installation, and the token endpoint, are open to a page on any origin: they say
/// nothing about a person, and the token endpoint authenticates the client in the request itself.</item>
/// <item>The routes a person calls with their own token are open to the origins clients registered.</item>
/// <item>Everything else, the administration API among it, is never opened to a page: it is done from a console
/// or a backend.</item>
/// </list>
/// </summary>
internal static class BrowserOrigins
{
    private static readonly string[] OpenPrefixes = ["/.well-known", "/api/v1/capabilities", "/connect/token", "/connect/userinfo"];

    private static readonly string[] RegisteredPrefixes = ["/api/v1/profile/", "/api/v1/logout", "/api/v1/users/password"];

    private const string Methods = "GET, POST, PUT, DELETE, OPTIONS";
    private const string DefaultHeaders = "authorization, content-type";

    public static void Use(WebApplication app) => app.Use(async (context, next) =>
    {
        var origin = context.Request.Headers.Origin.ToString();
        var path = context.Request.Path.Value ?? string.Empty;
        if (origin.Length == 0)
        {
            // What is open to every origin says so to a caller that did not name one, too: a cache in between may serve it to any page.
            if (OpenPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal)))
            {
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers.AccessControlAllowOrigin = "*";
                    return Task.CompletedTask;
                });
            }

            await next();
            return;
        }

        string? allow = null;
        if (OpenPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal)))
        {
            allow = "*";
        }
        else if (RegisteredPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal))
            && await context.RequestServices.GetRequiredService<RegisteredOrigins>().ContainsAsync(origin))
        {
            allow = origin;
        }

        if (allow is not null && allow != "*")
        {
            context.Response.Headers.Vary = StringValues.Concat(context.Response.Headers.Vary, "Origin");
        }

        if (HttpMethods.IsOptions(context.Request.Method) && context.Request.Headers.ContainsKey("Access-Control-Request-Method"))
        {
            // A preflight is answered here, whether it is let through or not: without the header the browser refuses the call.
            if (allow is not null)
            {
                context.Response.Headers.AccessControlAllowOrigin = allow;
                context.Response.Headers.AccessControlAllowMethods = Methods;
                var asked = context.Request.Headers["Access-Control-Request-Headers"].ToString();
                context.Response.Headers.AccessControlAllowHeaders = asked.Length > 0 ? asked : DefaultHeaders;
                context.Response.Headers.AccessControlMaxAge = "600";
            }

            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        if (allow is not null)
        {
            context.Response.OnStarting(() =>
            {
                context.Response.Headers.AccessControlAllowOrigin = allow;
                return Task.CompletedTask;
            });
        }

        await next();
    });
}
