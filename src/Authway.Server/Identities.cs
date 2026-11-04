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
    /// <summary>The claim that says which tenant a person belongs to; always present, and the one tenant's id here.</summary>
    public const string TenantId = "tenant_id";

    /// <summary>
    /// The identity a code, and the tokens it is exchanged for, are issued
    /// for. The access token says who and how to reach them; the ID token says
    /// what the application asked about them (<c>email</c>, <c>profile</c>).
    /// </summary>
    public static ClaimsIdentity Of(ApplicationUser user, IEnumerable<string> scopes, DateTimeOffset authenticatedAt, IEnumerable<string>? audiences = null)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Id.ToString());
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.EmailVerified, user.EmailConfirmed);
        identity.SetClaim(Claims.Name, user.DisplayName ?? user.Email);
        identity.SetClaim(TenantId, AdminEndpoints.DefaultTenantId.ToString());
        // How the person signed in, as a list — the form the claim has in the contract even with one entry.
        identity.AddClaim(new Claim(Claims.AuthenticationMethodReference, "[\"pwd\"]", "JSON_ARRAY"));
        identity.AddClaim(new Claim(Claims.AuthenticationTime, authenticatedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
        identity.SetScopes(scopes);

        // The resource servers the application is registered for: a resource server accepts a token that names it.
        if (audiences is not null)
        {
            identity.SetResources(audiences);
        }

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
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                break;
            case TenantId:
            case Claims.AuthenticationMethodReference:
                yield return Destinations.AccessToken;
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
