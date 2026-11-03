using System.Globalization;
using System.Security.Claims;
using Authway.Data;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>What the tokens say about the person they are issued to.</summary>
internal static class Identities
{
    /// <summary>
    /// The identity a code, and the tokens it is exchanged for, are issued
    /// for. The access token says who and how to reach them; the ID token says
    /// what the application asked about them (<c>email</c>, <c>profile</c>).
    /// </summary>
    public static ClaimsIdentity Of(ApplicationUser user, IEnumerable<string> scopes, DateTimeOffset authenticatedAt)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Id.ToString());
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.EmailVerified, user.EmailConfirmed);
        identity.SetClaim(Claims.Name, user.DisplayName ?? user.Email);
        identity.AddClaim(new Claim(Claims.AuthenticationTime, authenticatedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
        identity.SetScopes(scopes);
        identity.SetDestinations(DestinationsOf);
        return identity;
    }

    private static IEnumerable<string> DestinationsOf(Claim claim)
    {
        var scopes = claim.Subject!.GetScopes();
        switch (claim.Type)
        {
            case Claims.Subject:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                break;
            case Claims.AuthenticationTime:
                yield return Destinations.IdentityToken;
                break;
            case Claims.Email:
                yield return Destinations.AccessToken;
                if (scopes.Contains(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }

                break;
            case Claims.EmailVerified:
                if (scopes.Contains(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }

                break;
            case Claims.Name:
                yield return Destinations.AccessToken;
                if (scopes.Contains(Scopes.Profile))
                {
                    yield return Destinations.IdentityToken;
                }

                break;
        }
    }
}
