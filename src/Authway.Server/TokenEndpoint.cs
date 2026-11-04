using System.Security.Claims;
using Authway.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The token endpoint. OpenIddict has already authenticated the client and
/// validated the request when this runs; what is left is deciding who the token
/// is for and what it says.
/// </summary>
internal static class TokenEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext context,
        IOpenIddictApplicationManager applications,
        UserManager<ApplicationUser> users)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            return await ForTheClientAsync(request, applications);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            return await ForThePersonAsync(context, request, users, applications);
        }

        throw new InvalidOperationException($"The grant type {request.GrantType} is not handled.");
    }

    /// <summary>
    /// A code, or a refresh token, is exchanged for tokens for the person it was issued to,
    /// as long as they are still someone who can sign in: an account that has been locked
    /// or removed since gets nothing.
    /// </summary>
    private static async Task<IResult> ForThePersonAsync(HttpContext context, OpenIddictRequest request, UserManager<ApplicationUser> users, IOpenIddictApplicationManager applications)
    {
        var principal = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
            ?? throw new InvalidOperationException("The code or the refresh token cannot be read.");

        var user = await users.FindByIdAsync(principal.GetClaim(Claims.Subject) ?? string.Empty);
        if (user is null || !await users.CanBeUsedAsync(user))
        {
            return Results.Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The account is no longer allowed to sign in.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        // What the tokens say is read again, so that a change to the account (its name, its
        // address) reaches the tokens a refresh token issues; the scopes stay what was granted,
        // and the time of the sign-in stays the time the person signed in.
        var signedInAt = long.TryParse(principal.GetClaim(Claims.AuthenticationTime), out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : DateTimeOffset.UtcNow;
        var application = await applications.FindByClientIdAsync(request.ClientId!);
        if (application is not null && !await applications.IsOnAsync(application))
        {
            return Results.Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnauthorizedClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "This application is turned off.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var identity = Identities.Of(user, principal.GetScopes(), signedInAt, application is null ? null : await AudienceOfAsync(applications, application));
        if (principal.GetAuthorizationId() is { } authorization)
        {
            identity.SetAuthorizationId(authorization);
        }

        return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>The resource servers an application is registered for (its <c>audience</c>); none for an application registered for none.</summary>
    private static async Task<List<string>> AudienceOfAsync(IOpenIddictApplicationManager applications, object application)
    {
        var properties = await applications.GetPropertiesAsync(application);
        return properties.TryGetValue("audience", out var audience) && audience.ValueKind == System.Text.Json.JsonValueKind.Array
            ? [.. audience.EnumerateArray().Select(e => e.GetString()!)]
            : [];
    }

    /// <summary>The scopes an application is registered for.</summary>
    private static async Task<List<string>> ScopesOfAsync(IOpenIddictApplicationManager applications, object application)
    {
        var properties = await applications.GetPropertiesAsync(application);
        return properties.TryGetValue("scopes", out var scopes) && scopes.ValueKind == System.Text.Json.JsonValueKind.Array
            ? [.. scopes.EnumerateArray().Select(e => e.GetString()!)]
            : [];
    }

    /// <summary>A token for an application acting as itself: its subject is its client id.</summary>
    private static async Task<IResult> ForTheClientAsync(OpenIddictRequest request, IOpenIddictApplicationManager applications)
    {
        var application = await applications.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application details cannot be found.");
        if (!await applications.IsOnAsync(application))
        {
            return Results.Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnauthorizedClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "This application is turned off.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        // The token is for the resource servers the application is registered for, or the one among them it names.
        var registered = await AudienceOfAsync(applications, application);
        var named = request.GetParameter("audience")?.ToString();
        if (!string.IsNullOrEmpty(named) && !registered.Contains(named, StringComparer.Ordinal))
        {
            return Results.Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The application is not registered for that resource server.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);
        identity.SetClaim(Claims.Subject, await applications.GetClientIdAsync(application));
        identity.SetClaim(Claims.Name, await applications.GetDisplayNameAsync(application));
        identity.SetClaim(Identities.TenantId, AdminEndpoints.DefaultTenantId.ToString());

        // The scopes granted: the ones asked for, or, when the request names none, those the application is registered for.
        var requested = request.GetScopes();
        identity.SetScopes(requested.Length > 0 ? requested : await ScopesOfAsync(applications, application));
        identity.SetResources(string.IsNullOrEmpty(named) ? registered : [named]);
        identity.SetDestinations(static _ => [Destinations.AccessToken]);

        return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}
