using System.Globalization;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// What the person invited uses: the screen shows the invitation from the link's token, then accepts it
/// with a password, and the account exists. No key is needed — the token is the proof, and it cannot be
/// guessed. Signing in with another provider is not offered here, so the routes that belong to it answer
/// as the contract says an installation without it does.
/// </summary>
internal static class InvitationPublicEndpoints
{
    /// <summary>The least length of a password: what every tenant gets in the contract.</summary>
    public const int PasswordMinLength = 8;

    public static void Map(IEndpointRouteBuilder app)
    {
        var invitations = app.MapGroup("/api/v1/invitations").RequireRateLimiting(SignInLimit.Policy);
        invitations.MapGet("/token/{token}", ShowAsync);
        invitations.MapPost("/accept", AcceptAsync);
        invitations.MapGet("/token/{token}/social/{provider}", NoProvider);
        invitations.MapGet("/receipts/{id}", NoReceipt);
    }

    private static async Task<IResult> ShowAsync(string token, AuthwayDbContext db, IOpenIddictApplicationManager applications, TimeProvider time)
    {
        var invitation = await FindByTokenAsync(db, token);
        if (invitation is null)
        {
            return Problems.Refuse(StatusCodes.Status404NotFound, "invalid_token", "That invitation was not found, or it has expired.");
        }

        var status = InvitationEndpoints.StatusOf(invitation, time.GetUtcNow());
        if (status != Invitation.Pending)
        {
            return Problems.Refuse(StatusCodes.Status400BadRequest, "invitation_not_acceptable", "That invitation cannot be accepted.", extra: new Dictionary<string, object> { ["invitation_status"] = status });
        }

        var shown = new Dictionary<string, object?>
        {
            ["id"] = invitation.Id.ToString(),
            ["email"] = invitation.Email,
            ["tenant_name"] = AdminEndpoints.DefaultTenantName,
            ["inviter_name"] = invitation.InviterName,
            ["expires_at"] = invitation.ExpiresAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        };
        if (invitation.Message is not null)
        {
            shown["message"] = invitation.Message;
        }

        if (await ApplicationOfAsync(applications, invitation) is { } app)
        {
            shown["client"] = app;
        }

        return Results.Json(new Dictionary<string, object?> { ["invitation"] = shown, ["password_min_length"] = PasswordMinLength });
    }

    private static async Task<IResult> AcceptAsync(HttpContext context, AuthwayDbContext db, UserManager<ApplicationUser> users, TimeProvider time)
    {
        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        if (String(body!.Value, "token") is not { Length: > 0 } token)
        {
            return Refuse("invalid_request", "A token is required.", "token");
        }

        var password = String(body.Value, "password") ?? string.Empty;
        if (password.Length < PasswordMinLength)
        {
            return Problems.Refuse(
                StatusCodes.Status400BadRequest,
                "password_too_short",
                $"The password must be at least {PasswordMinLength} characters.",
                field: "password",
                extra: new Dictionary<string, object> { ["min_length"] = PasswordMinLength });
        }

        var invitation = await FindByTokenAsync(db, token);
        var now = time.GetUtcNow();

        // The invitation is claimed first, in one statement that only a pending, unexpired one satisfies,
        // so that two answers to the same link make one account.
        var claimed = invitation is null ? 0 : await db.Invitations
            .Where(i => i.Id == invitation.Id && i.Status == Invitation.Pending && i.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(i => i.Status, Invitation.Accepted).SetProperty(i => i.AcceptedAt, now).SetProperty(i => i.UpdatedAt, now));
        if (invitation is null || claimed == 0)
        {
            return Refuse("invitation_not_accepted", "That invitation cannot be accepted.");
        }

        var name = String(body.Value, "name")?.Trim();
        var account = new ApplicationUser { UserName = invitation.Email, Email = invitation.Email, EmailConfirmed = true, DisplayName = string.IsNullOrEmpty(name) ? null : name };
        var created = await users.CreateAsync(account, password);
        if (!created.Succeeded)
        {
            // The invitation was not used up by an account that was not made.
            await db.Invitations.Where(i => i.Id == invitation.Id).ExecuteUpdateAsync(set => set.SetProperty(i => i.Status, Invitation.Pending).SetProperty(i => i.AcceptedAt, (DateTimeOffset?)null));
            return Refuse("invitation_not_accepted", created.Errors.FirstOrDefault()?.Description ?? "The account could not be made.");
        }

        await db.Invitations.Where(i => i.Id == invitation.Id).ExecuteUpdateAsync(set => set.SetProperty(i => i.AcceptedBy, account.Id));
        return Results.Json(new Dictionary<string, object>
        {
            ["message"] = "Invitation accepted.",
            ["user"] = new Dictionary<string, object> { ["id"] = account.Id.ToString(), ["email"] = account.Email! },
        });
    }

    /// <summary>Signing in with another provider is not offered: the browser goes back to the screen and says so.</summary>
    private static IResult NoProvider(string token, HttpContext context, IConfiguration configuration)
    {
        var baseUrl = BootstrapConfig.UiAddress(context, configuration);
        return Results.Redirect($"{baseUrl}/invitation/accept?error=provider_unavailable&token={Uri.EscapeDataString(token)}");
    }

    /// <summary>A receipt is made when an invitation is accepted with a provider, which this installation does not offer.</summary>
    private static IResult NoReceipt() =>
        Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "There is no such receipt.");

    private static async Task<Invitation?> FindByTokenAsync(AuthwayDbContext db, string token)
    {
        var hash = InvitationEndpoints.Hash(token);
        return await db.Invitations.AsNoTracking().FirstOrDefaultAsync(i => i.TokenHash == hash);
    }

    /// <summary>
    /// The application to send the person to once they have accepted: the one the invitation names; when it
    /// names none, the only one with an https address of its own to start a sign-in or to be visited at.
    /// More than one, or none, and which application is meant is not guessed.
    /// </summary>
    private static async Task<Dictionary<string, object?>?> ApplicationOfAsync(IOpenIddictApplicationManager applications, Invitation invitation)
    {
        if (invitation.ClientId is not null)
        {
            return await applications.FindByClientIdAsync(invitation.ClientId) is { } named
                ? await InvitationEndpoints.InvitationApp(applications, named, invitation.ClientId)
                : null;
        }

        var candidates = new List<Dictionary<string, object?>>();
        await foreach (var application in applications.ListAsync())
        {
            var clientId = await applications.GetClientIdAsync(application);
            if (clientId is null)
            {
                continue;
            }

            var app = await InvitationEndpoints.InvitationApp(applications, application, clientId);
            if (app.TryGetValue("initiate_login_uri", out var login) && IsHttps(login) || app.TryGetValue("client_uri", out var home) && IsHttps(home))
            {
                candidates.Add(app);
            }
        }

        return candidates.Count == 1 ? candidates[0] : null;
    }

    private static bool IsHttps(object? address) => address is string s && Uri.TryCreate(s, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
}
