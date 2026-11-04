using System.Security.Claims;
using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
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

    /// <summary>The route of the consent screen; it is handed the flow id.</summary>
    public const string ConsentScreen = "/consent";

    public static async Task<IResult> HandleAsync(
        HttpContext context,
        IOpenIddictApplicationManager applications,
        UserManager<ApplicationUser> users,
        IFlowStore flows,
        Consents consents,
        TimeProvider time)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var application = await applications.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application details cannot be found.");

        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var authenticatedAt = AuthTime.Of(session);

        // The application can ask for a sign-in that is not an old one: always (prompt=login), or
        // no older than so many seconds (max_age; 0 is the same as always). A session that is
        // older than that is not the answer, however valid it still is. The age is counted in
        // whole seconds, so that a sign-in a moment ago is not too old for max_age=0.
        var signInAgain = request.HasPromptValue(PromptValues.Login)
            || (request.MaxAge is { } maxAge && authenticatedAt is { } at && (long)(time.GetUtcNow() - at).TotalSeconds > maxAge);

        if (authenticatedAt is null || signInAgain)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Refuse(Errors.LoginRequired, "The user is not signed in.");
            }

            var flow = flows.Open(
                FlowKind.Login,
                request.ClientId!,
                await applications.GetDisplayNameAsync(application) ?? request.ClientId!,
                request.GetScopes(),
                ResumeUrl(context, PromptValues.Login),
                HintsOf(request));
            return Results.Redirect($"{LoginScreen}?flow={Uri.EscapeDataString(flow.Id)}");
        }

        var user = await users.GetUserAsync(session.Principal!);
        if (user is null)
        {
            return Refuse(Errors.LoginRequired, "The user is not signed in.");
        }

        // An application the account holder owns (consent type implicit) is not asked about; any other is,
        // unless the person has already said yes to what it asks for.
        var skipsConsent = await applications.GetConsentTypeAsync(application) is ConsentTypes.Implicit;
        var subject = user.Id.ToString();
        var requested = request.GetScopes();
        var consent = await consents.FindAsync(
            subject,
            application,
            requested,
            ignoreKept: !skipsConsent && request.HasPromptValue(PromptValues.Consent),
            answeredId: request.GetParameter(Consents.AnsweredParameter)?.ToString());
        if (consent is null && skipsConsent)
        {
            consent = await consents.GrantAsync(subject, application, requested, keep: true);
        }

        if (consent is null)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Refuse(Errors.ConsentRequired, "The user has not allowed this application.");
            }

            var ask = flows.Open(
                FlowKind.Consent,
                request.ClientId!,
                await applications.GetDisplayNameAsync(application) ?? request.ClientId!,
                requested,
                ResumeUrl(context, PromptValues.Consent),
                HintsOf(request),
                subject,
                rejectTo: Denied(request));
            return Results.Redirect($"{ConsentScreen}?flow={Uri.EscapeDataString(ask.Id)}");
        }

        var identity = Identities.Of(user, consent.Scopes, authenticatedAt.Value);
        identity.SetAuthorizationId(consent.AuthorizationId);
        return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>The request the person was sent here with, minus the demand (sign in again, be asked again) that they are about to meet.</summary>
    private static string ResumeUrl(HttpContext context, string answered)
    {
        IEnumerable<KeyValuePair<string, StringValues>> parameters = context.Request.HasFormContentType
            ? context.Request.Form
            : context.Request.Query;

        var kept = new List<KeyValuePair<string, StringValues>>();
        foreach (var (name, value) in parameters)
        {
            if (name == Consents.AnsweredParameter)
            {
                continue;
            }

            if (name == Parameters.Prompt)
            {
                var rest = string.Join(' ', value.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(p => p != answered));
                if (rest.Length > 0)
                {
                    kept.Add(new(name, rest));
                }

                continue;
            }

            kept.Add(new(name, value));
        }

        // An absolute address, as the contract's redirect_to is: the screens may be served from another
        // origin than this one, where an address with no origin would lead somewhere else.
        return $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}{QueryString.Create(kept)}";
    }

    /// <summary>Where the application is told the person said no.</summary>
    private static string Denied(OpenIddictRequest request)
    {
        var parameters = new Dictionary<string, string?>
        {
            [Parameters.Error] = Errors.AccessDenied,
            [Parameters.ErrorDescription] = "The user denied the request.",
            [Parameters.State] = request.State,
        };
        return QueryHelpers.AddQueryString(request.RedirectUri!, parameters.Where(p => !string.IsNullOrEmpty(p.Value)));
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
