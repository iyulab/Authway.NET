using System.Security.Claims;
using Authway.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The person a call is made for, from the access token it carries: what the contract calls a user token.
/// The subject of a token an application holds for itself is the application, not a person, and an account
/// that is suspended or locked out is nobody a call is answered for.
/// </summary>
internal static class UserToken
{
    /// <summary>The person the token is of, with the token's principal; <c>null</c> person when the call is not one a person made, already answered with a 401.</summary>
    public static async Task<(ApplicationUser? User, ClaimsPrincipal? Principal)> AuthenticateAsync(HttpContext context, UserManager<ApplicationUser> users)
    {
        var result = await context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        var subject = result.Succeeded ? result.Principal?.GetClaim(Claims.Subject) : null;
        var user = subject is not null && Guid.TryParse(subject, out _) ? await users.FindByIdAsync(subject) : null;
        if (user is null || !await users.CanBeUsedAsync(user))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
            return (null, null);
        }

        return (user, result.Principal);
    }

    public static IResult Unauthorized() =>
        Problems.Refuse(StatusCodes.Status401Unauthorized, "unauthorized", "A person's access token is required.");
}
