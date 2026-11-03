using System.Security.Claims;
using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The authorization endpoint. OpenIddict has validated the request when this
/// runs. Where the browser has a session the application can use, the answer
/// is a code; where it has none the person signs in first, on a screen the
/// login flow API serves, and the browser comes back here.
/// </summary>
internal static class AuthorizationEndpoint
{
    /// <summary>The route of the sign-in screen; it is handed the flow id.</summary>
    public const string LoginScreen = "/login";

    public static async Task<IResult> HandleAsync(
        HttpContext context,
        IOpenIddictApplicationManager applications,
        UserManager<ApplicationUser> users,
        IFlowStore flows)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var application = await applications.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application details cannot be found.");

        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var signInAgain = request.HasPromptValue(PromptValues.Login);

        if (!session.Succeeded || signInAgain)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Refuse(Errors.LoginRequired, "The user is not signed in.");
            }

            var flow = flows.Open(
                request.ClientId!,
                await applications.GetDisplayNameAsync(application) ?? request.ClientId!,
                request.GetScopes(),
                ResumeUrl(context),
                HintsOf(request));
            return Results.Redirect($"{LoginScreen}?flow={Uri.EscapeDataString(flow.Id)}");
        }

        var user = await users.GetUserAsync(session.Principal!);
        if (user is null)
        {
            return Refuse(Errors.LoginRequired, "The user is not signed in.");
        }

        if (await applications.GetConsentTypeAsync(application) is ConsentTypes.Explicit)
        {
            // Asking for consent is its own flow; until it is there, an application that needs it cannot be served.
            return Refuse(Errors.ConsentRequired, "The application needs the user's consent, which this server cannot ask for yet.");
        }

        return Results.SignIn(
            new ClaimsPrincipal(Identities.Of(user, request.GetScopes())),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>The request the person was sent here with, minus the demand to sign in again, which is what they are about to do.</summary>
    private static string ResumeUrl(HttpContext context)
    {
        IEnumerable<KeyValuePair<string, StringValues>> parameters = context.Request.HasFormContentType
            ? context.Request.Form
            : context.Request.Query;

        var kept = new List<KeyValuePair<string, StringValues>>();
        foreach (var (name, value) in parameters)
        {
            if (name == Parameters.Prompt)
            {
                var rest = string.Join(' ', value.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(p => p != PromptValues.Login));
                if (rest.Length > 0)
                {
                    kept.Add(new(name, rest));
                }

                continue;
            }

            kept.Add(new(name, value));
        }

        return context.Request.PathBase + context.Request.Path + QueryString.Create(kept);
    }

    private static FlowHints HintsOf(OpenIddictRequest request)
    {
        // The screen offers the password form only for now; a way of signing in it cannot offer is not a hint.
        var connection = request.GetParameter("connection")?.ToString();
        return new FlowHints(
            connection == LoginFlowEndpoints.PasswordMethod ? connection : null,
            string.IsNullOrWhiteSpace(request.LoginHint) ? null : request.LoginHint,
            (request.UiLocales ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    private static IResult Refuse(string error, string description) =>
        Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
