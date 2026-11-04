using System.Globalization;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// What a signed-in person does with their own account, called with their own access token: read the profile
/// and choose another password. A password changed because it leaked must not leave the leak signed in, so
/// the sessions opened with the old one end.
/// </summary>
internal static class AccountEndpoints
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/profile/me", ProfileAsync);
        app.MapPost("/api/v1/users/password", ChangePasswordAsync).RequireRateLimiting(SignInLimit.Policy);
    }

    private static async Task<IResult> ProfileAsync(HttpContext context, UserManager<ApplicationUser> users)
    {
        var (user, _) = await UserToken.AuthenticateAsync(context, users);
        if (user is null)
        {
            return UserToken.Unauthorized();
        }

        var profile = new Dictionary<string, object?>
        {
            ["id"] = user.Id.ToString(),
            ["email"] = user.Email,
            ["name"] = user.DisplayName,
            ["email_verified"] = user.EmailConfirmed,
            ["has_password"] = await users.HasPasswordAsync(user),
            ["created_at"] = user.CreatedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        };
        return Results.Json(profile);
    }

    private static async Task<IResult> ChangePasswordAsync(
        HttpContext context,
        AuthwayDbContext db,
        UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations,
        AuditTrail audit)
    {
        var (user, _) = await UserToken.AuthenticateAsync(context, users);
        if (user is null)
        {
            return UserToken.Unauthorized();
        }

        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        if (String(body!.Value, "new_password") is not { } password)
        {
            return Refuse("invalid_request", "A new password is required.", "new_password");
        }

        // The current password proves it is the person; wrong ones count like wrong sign-ins and lock the account out alike.
        // An account with no password has none to prove with — setting a first one is the account screen's, which this
        // installation does not have, since it signs people in by password alone.
        var current = String(body.Value, "current_password") ?? string.Empty;
        var proved = await users.HasPasswordAsync(user) && (await signIn.CheckPasswordSignInAsync(user, current, lockoutOnFailure: true)).Succeeded;
        if (!proved)
        {
            return Refuse("invalid_current_password", "The current password is not right.", "current_password");
        }

        if (password.Length < InvitationPublicEndpoints.PasswordMinLength)
        {
            return Problems.Refuse(
                StatusCodes.Status400BadRequest,
                "password_too_short",
                $"The password must be at least {InvitationPublicEndpoints.PasswordMinLength} characters.",
                field: "new_password",
                extra: new Dictionary<string, object> { ["min_length"] = InvitationPublicEndpoints.PasswordMinLength });
        }

        var changed = await users.ChangePasswordAsync(user, current, password);
        if (!changed.Succeeded)
        {
            return Refuse("password_too_short", changed.Errors.FirstOrDefault()?.Description ?? "The password cannot be used.", "new_password");
        }

        // Every session ends: the browsers' with the account's security stamp, and what the person was given (access
        // and refresh tokens, remembered consents) is revoked. A session is not told from another here: a sign-in to an
        // application the person has already agreed to reuses that agreement, so tokens of two sign-ins share it, and
        // keeping "this" session would keep the others. The caller signs in again with the password it just chose.
        var subject = user.Id.ToString();
        await tokens.RevokeBySubjectAsync(subject);
        await authorizations.RevokeBySubjectAsync(subject);

        // A link to choose a password that was asked for before this one was chosen is moot.
        await EmailEndpoints.SpendResetLinksAsync(db, user.Id, DateTimeOffset.UtcNow);
        await audit.RecordAsync(context, AuditActions.UserPasswordChanged, "user", subject, actorId: user.Id, actorEmail: user.Email);
        return Results.Json(new Dictionary<string, object> { ["message"] = "Password changed successfully", ["sessions_ended"] = "all" });
    }
}
