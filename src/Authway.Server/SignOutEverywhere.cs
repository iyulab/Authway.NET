using Authway.Data;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

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
        IOpenIddictAuthorizationManager authorizations,
        AuditTrail audit)
    {
        var (user, _) = await UserToken.AuthenticateAsync(context, users);
        if (user is null)
        {
            return UserToken.Unauthorized();
        }

        var subject = user.Id.ToString();
        await users.UpdateSecurityStampAsync(user);
        await tokens.RevokeBySubjectAsync(subject);
        await authorizations.RevokeBySubjectAsync(subject);
        await audit.RecordAsync(context, AuditActions.UserLogout, "user", subject, actorId: user.Id, actorEmail: user.Email,
            details: new Dictionary<string, object?> { ["scope"] = "everywhere" });
        return Results.Json(new { success = true, message = "Signed out everywhere." });
    }
}
