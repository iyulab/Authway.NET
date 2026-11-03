using System.Security.Claims;
using Microsoft.AspNetCore;
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
    public static async Task<IResult> HandleAsync(HttpContext context, IOpenIddictApplicationManager applications)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            return await ForTheClientAsync(request, applications);
        }

        // The other grants the server allows (a code and a refresh token) come with the
        // sign-in flow that issues them, and are handled and tested together with it.
        throw new InvalidOperationException($"The grant type {request.GrantType} is not handled yet.");
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
