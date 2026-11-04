using Microsoft.Extensions.FileProviders;

namespace Authway.Server;

/// <summary>
/// Serves the bundled sign-in screens from the directory the installation points at
/// (<c>Authway:Ui:Directory</c>, the build of the login UI), on the address the API is on.
/// A screen is a page of a single-page application: any address that is not the API's
/// is answered with its <c>index.html</c>, and its <c>config.js</c> says where the API is.
/// </summary>
internal static class LoginUi
{
    /// <summary>The prefixes the server answers itself; an address under one that it does not know is not found, whatever a screen would do.</summary>
    private static readonly string[] ServerPaths = ["/api/", "/connect/", "/.well-known/"];

    public static void Use(WebApplication app)
    {
        var directory = app.Configuration["Authway:Ui:Directory"];
        if (string.IsNullOrWhiteSpace(directory))
        {
            return;
        }

        if (!Directory.Exists(directory))
        {
            throw new InvalidOperationException($"Authway:Ui:Directory is set to {directory}, which is not a directory: the sign-in screens are not there.");
        }

        var files = new PhysicalFileProvider(Path.GetFullPath(directory));
        var apiUrl = (app.Configuration["Authway:Ui:ApiUrl"] ?? string.Empty).TrimEnd('/');

        // The screen is built once for any address; this file is what tells it where it runs (see
        // runtime-config.schema.json). It is served from here whether or not the build holds one, and never cached.
        app.Use(async (context, next) =>
        {
            if (HttpMethods.IsGet(context.Request.Method) && context.Request.Path == "/config.js")
            {
                context.Response.ContentType = "text/javascript; charset=utf-8";
                context.Response.Headers.CacheControl = "no-store";
                var config = System.Text.Json.JsonSerializer.Serialize(new { apiUrl });
                await context.Response.WriteAsync($"window.__AUTHWAY_CONFIG__ = {config};");
                return;
            }

            await next();
        });

        app.UseStaticFiles(new StaticFileOptions { FileProvider = files });

        app.MapFallback(async context =>
        {
            var file = files.GetFileInfo("index.html");
            if (!HttpMethods.IsGet(context.Request.Method) || !file.Exists || ServerPaths.Any(p => context.Request.Path.StartsWithSegments(p.TrimEnd('/'))))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers.CacheControl = "no-cache";
            await context.Response.SendFileAsync(file);
        });
    }
}
