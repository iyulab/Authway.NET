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
            return await ForThePersonAsync(context, request, users);
        }

        throw new InvalidOperationException($"The grant type {request.GrantType} is not handled.");
    }

    /// <summary>
    /// A code, or a refresh token, is exchanged for tokens for the person it was issued to,
    /// as long as they are still someone who can sign in: an account that has been locked
    /// or removed since gets nothing.
    /// </summary>
    private static async Task<IResult> ForThePersonAsync(HttpContext context, OpenIddictRequest request, UserManager<ApplicationUser> users)
    {
        var principal = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
            ?? throw new InvalidOperationException("The code or the refresh token cannot be read.");

        var user = await users.FindByIdAsync(principal.GetClaim(Claims.Subject) ?? string.Empty);
        if (user is null || await users.IsLockedOutAsync(user))
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
        // address) reaches the tokens a refresh token issues; the scopes stay what was granted.
        return Results.SignIn(
            new ClaimsPrincipal(Identities.Of(user, principal.GetScopes())),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>A token for an application acting as itself: its subject is its client id.</summary>
    private static async Task<IResult> ForTheClientAsync(OpenIddictRequest request, IOpenIddictApplicationManager applications)
    {
        var application = await applications.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application details cannot be found.");

        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);
        identity.SetClaim(Claims.Subject, await applications.GetClientIdAsync(application));
        identity.SetClaim(Claims.Name, await applications.GetDisplayNameAsync(application));
        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(static _ => [Destinations.AccessToken]);

        return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}
