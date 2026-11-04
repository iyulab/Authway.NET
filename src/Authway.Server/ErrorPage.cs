using Microsoft.AspNetCore;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Authway.Server;

/// <summary>
/// A request that cannot be answered to the application — it named no address, or one that is not registered —
/// must not be answered by sending the browser to that address, and a bare error body is no answer to a
/// person. It is sent to the sign-in screens' error page, which says what went wrong
/// (<c>/error?error=…&amp;error_description=…</c>); a request that can be answered to the application keeps
/// its error in the application's redirect, as the standards have it.
/// </summary>
internal static class ErrorPage
{
    public static void Add(OpenIddictServerBuilder options)
    {
        options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
            builder.UseInlineHandler(context => Redirect(context, context.Response.Error, context.Response.ErrorDescription, context.RedirectUri)));
        options.AddEventHandler<ApplyEndSessionResponseContext>(builder =>
            builder.UseInlineHandler(context => Redirect(context, context.Response.Error, context.Response.ErrorDescription, context.PostLogoutRedirectUri)));
    }

    private static ValueTask Redirect(BaseRequestContext context, string? error, string? description, string? answerTo)
    {
        if (error is null || !string.IsNullOrEmpty(answerTo) || context.Transaction.GetHttpRequest()?.HttpContext is not { } http)
        {
            return ValueTask.CompletedTask;
        }

        var ui = BootstrapConfig.UiAddress(http, http.RequestServices.GetRequiredService<IConfiguration>());
        var query = $"error={Uri.EscapeDataString(error)}" + (string.IsNullOrEmpty(description) ? string.Empty : $"&error_description={Uri.EscapeDataString(description)}");
        http.Response.Redirect($"{ui}/error?{query}");
        context.HandleRequest();
        return ValueTask.CompletedTask;
    }
}
