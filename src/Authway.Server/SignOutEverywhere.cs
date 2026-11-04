using Authway.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// <c>POST /api/v1/logout</c>: the signed-in person ends every session they have, on every device and for
/// every application. The caller proves who it is with the person's own access token; the browsers'
/// sessions stop being good (the account's security stamp changes), and what the person was given —
/// access and refresh tokens, remembered consents — is revoked, the token used for this call with it.
/// </summary>
internal static class SignOutEverywhere
{
    public static void Map(IEndpointRouteBuilder app) => app.MapPost("/api/v1/logout", HandleAsync);

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        UserManager<ApplicationUser> users,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations)
    {
        var result = await context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        var subject = result.Succeeded ? result.Principal?.GetClaim(Claims.Subject) : null;

        // The subject of a token an application holds for itself is the application, not a person.
        var user = subject is not null && Guid.TryParse(subject, out _) ? await users.FindByIdAsync(subject) : null;
        if (user is null || await users.IsLockedOutAsync(user))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
            return Problems.Refuse(StatusCodes.Status401Unauthorized, "unauthorized", "A person's access token is required.");
        }

        await users.UpdateSecurityStampAsync(user);
        await tokens.RevokeBySubjectAsync(subject!);
        await authorizations.RevokeBySubjectAsync(subject!);
        return Results.Json(new { success = true, message = "Signed out everywhere." });
    }
}
