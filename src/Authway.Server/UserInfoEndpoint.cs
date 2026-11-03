using Authway.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// What an application may ask about the person its access token is for
/// (OpenID Connect Core 5.3). OpenIddict has checked the token; the answer is
/// read from the account, so it is what is true now, and it follows the scopes
/// the token was granted: <c>email</c> for the address, <c>profile</c> for the name.
/// </summary>
internal static class UserInfoEndpoint
{
    public static async Task<IResult> HandleAsync(HttpContext context, UserManager<ApplicationUser> users)
    {
        var principal = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
            ?? throw new InvalidOperationException("The access token cannot be read.");

        var user = await users.FindByIdAsync(principal.GetClaim(Claims.Subject) ?? string.Empty);
        if (user is null || await users.IsLockedOutAsync(user))
        {
            // A token outlives an account that has since been removed or locked; it stops being good for this.
            return Results.Challenge(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The access token is no longer valid.",
                }),
                [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var claims = new Dictionary<string, object> { [Claims.Subject] = user.Id.ToString() };
        if (principal.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email!;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (principal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.DisplayName ?? user.Email!;
        }

        return Results.Ok(claims);
    }
}
