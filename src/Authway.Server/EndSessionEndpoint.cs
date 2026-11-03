using Authway.Server.Flows;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The end-session endpoint (OpenID Connect RP-Initiated Logout). An application
/// sends the browser here; the person is asked on the sign-out screen, which
/// finishes the flow through the login flow API, and the browser then goes on to
/// where the application asked.
/// </summary>
internal static class EndSessionEndpoint
{
    /// <summary>The route of the sign-out screen; it is handed the flow id.</summary>
    public const string LogoutScreen = "/logout";

    /// <summary>Where the browser goes when the application did not say.</summary>
    private const string Home = "/";

    private static readonly FlowHints NoHints = new(null, null, []);

    public static async Task<IResult> HandleAsync(HttpContext context, IOpenIddictApplicationManager applications, IFlowStore flows)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // OpenIddict has checked the ID token hint and that the address to return to is one the application registered.
        var hint = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        var clientId = hint?.GetClaim(Claims.AuthorizedParty) ?? hint?.GetAudiences().FirstOrDefault() ?? string.Empty;
        var application = clientId.Length == 0 ? null : await applications.FindByClientIdAsync(clientId);
        var clientName = application is null ? string.Empty : await applications.GetDisplayNameAsync(application) ?? clientId;

        var flow = flows.Open(FlowKind.Logout, clientId, clientName, [], Destination(request), NoHints);
        return Results.Redirect($"{LogoutScreen}?flow={Uri.EscapeDataString(flow.Id)}");
    }

    private static string Destination(OpenIddictRequest request) =>
        string.IsNullOrEmpty(request.PostLogoutRedirectUri)
            ? Home
            : string.IsNullOrEmpty(request.State)
                ? request.PostLogoutRedirectUri
                : QueryHelpers.AddQueryString(request.PostLogoutRedirectUri, Parameters.State, request.State);
}
