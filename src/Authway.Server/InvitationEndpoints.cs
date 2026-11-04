using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Authway.Data;
using Authway.Server.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// Invitations (<c>/api/v1/invitations</c>): onboarding here is by invitation only, so an administrator
/// invites an address and the person follows the mailed link to choose a password. Only the hash of the
/// link's token is kept. An invitation that is pending past its expiry reads as expired.
/// </summary>
internal static partial class InvitationEndpoints
{
    private const int MostPerPage = 100;
    private const int DefaultPerPage = 20;

    /// <summary>How long a link works.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

    /// <summary>Who an invitation names as its sender when no person sent it (the administration key).</summary>
    private const string SystemInviter = "Authway";

    private static readonly string[] Statuses = ["pending", "accepted", "expired", "revoked"];

    public static void Map(RouteGroupBuilder admin)
    {
        admin.MapGet("/invitations", ListAsync);
        admin.MapPost("/invitations", CreateAsync);
        admin.MapGet("/invitations/{id}", GetAsync);
        admin.MapDelete("/invitations/{id}", RevokeAsync);
        admin.MapPost("/invitations/{id}/resend", ResendAsync);
    }

    // ---- the calls ------------------------------------------------------------------------

    private static async Task<IResult> ListAsync(HttpContext context, AuthwayDbContext db, IOpenIddictApplicationManager applications, TimeProvider time)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var query = context.Request.Query;
        var status = query["status"].ToString();
        if (status.Length > 0 && !Statuses.Contains(status))
        {
            return Refuse("invalid_request", "status must be one of pending, accepted, expired, revoked.", "status");
        }

        var limit = Math.Clamp(int.TryParse(query["limit"], CultureInfo.InvariantCulture, out var l) ? l : DefaultPerPage, 1, MostPerPage);
        var offset = Math.Max(int.TryParse(query["offset"], CultureInfo.InvariantCulture, out var o) ? o : 0, 0);

        // The set is read and filtered here: whether one is expired depends on the time of the question.
        var now = time.GetUtcNow();
        var all = (await db.Invitations.AsNoTracking().ToListAsync()).Where(i => status.Length == 0 || StatusOf(i, now) == status).ToList();
        var page = all.OrderByDescending(i => i.CreatedAt).Skip(offset).Take(limit).ToList();

        var invitations = new List<Dictionary<string, object?>>();
        foreach (var invitation in page)
        {
            invitations.Add(await ToJsonAsync(applications, invitation, now));
        }

        return Results.Json(new Dictionary<string, object> { ["invitations"] = invitations, ["total"] = all.Count, ["limit"] = limit, ["offset"] = offset });
    }

    private static async Task<IResult> GetAsync(string id, AuthwayDbContext db, IOpenIddictApplicationManager applications, TimeProvider time)
    {
        var (invitation, refusal) = await FindAsync(db, id, track: false);
        return refusal ?? Results.Json(new { invitation = await ToJsonAsync(applications, invitation!, time.GetUtcNow()) });
    }

    private static async Task<IResult> CreateAsync(
        HttpContext context,
        AuthwayDbContext db,
        UserManager<ApplicationUser> users,
        IOpenIddictApplicationManager applications,
        IMailSender mail,
        IConfiguration configuration,
        ILoggerFactory logs,
        TimeProvider time)
    {
        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        if (TenantRefusal(context, body!.Value) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var email = String(body.Value, "email")?.Trim();
        if (!IsAddress(email))
        {
            return Refuse("invalid_request", "A valid email address is required.", "email");
        }

        var clientId = String(body.Value, "client_id");
        if (!string.IsNullOrEmpty(clientId) && await applications.FindByClientIdAsync(clientId) is null)
        {
            return Refuse("unknown_client", "That application is not one of this tenant's clients.", "client_id");
        }

        if (await users.FindByEmailAsync(email!) is not null)
        {
            return Problems.Refuse(StatusCodes.Status409Conflict, "user_already_member", "That address already has an account.", field: "email");
        }

        var normalized = Normalize(email!);
        var now = time.GetUtcNow();
        var open = await db.Invitations.Where(i => i.NormalizedEmail == normalized && i.Status == Invitation.Pending && i.ExpiresAt > now).AnyAsync();
        if (open)
        {
            return Problems.Refuse(StatusCodes.Status409Conflict, "invitation_already_pending", "That address has already been invited.", field: "email");
        }

        var token = NewToken();
        var invitation = new Invitation
        {
            Id = Guid.NewGuid(),
            Email = email!,
            NormalizedEmail = normalized,
            Message = NullIfEmpty(String(body.Value, "message")),
            InviterName = SystemInviter,
            ClientId = NullIfEmpty(clientId),
            TokenHash = Hash(token),
            Status = Invitation.Pending,
            ExpiresAt = now + Lifetime,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Invitations.Add(invitation);
        await db.SaveChangesAsync();

        var mailed = await TryMailAsync(mail, invitation, token, context, configuration, logs);
        return Results.Json(
            new Dictionary<string, object>
            {
                ["invitation"] = new Dictionary<string, object>
                {
                    ["id"] = invitation.Id.ToString(),
                    ["email"] = invitation.Email,
                    ["status"] = Invitation.Pending,
                    ["expires_at"] = Iso(invitation.ExpiresAt),
                },
                ["message"] = mailed ? "Invitation created and emailed." : "Invitation created, but the email could not be sent; resend it once mail works.",
            },
            statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> RevokeAsync(string id, AuthwayDbContext db, TimeProvider time)
    {
        var (invitation, refusal) = await FindAsync(db, id, track: true);
        if (refusal is not null)
        {
            return refusal;
        }

        var now = time.GetUtcNow();
        if (StatusOf(invitation!, now) != Invitation.Pending)
        {
            return NotPending();
        }

        invitation!.Status = Invitation.Revoked;
        invitation.UpdatedAt = now;
        await db.SaveChangesAsync();
        return Results.Json(new { message = "Invitation revoked." });
    }

    private static async Task<IResult> ResendAsync(string id, HttpContext context, AuthwayDbContext db, IMailSender mail, IConfiguration configuration, ILoggerFactory logs, TimeProvider time)
    {
        var (invitation, refusal) = await FindAsync(db, id, track: true);
        if (refusal is not null)
        {
            return refusal;
        }

        var now = time.GetUtcNow();
        if (StatusOf(invitation!, now) != Invitation.Pending)
        {
            return NotPending();
        }

        // A new link, which replaces the old one, and the time starts again.
        var token = NewToken();
        invitation!.TokenHash = Hash(token);
        invitation.ExpiresAt = now + Lifetime;
        invitation.UpdatedAt = now;
        await db.SaveChangesAsync();

        var mailed = await TryMailAsync(mail, invitation, token, context, configuration, logs);
        return Results.Json(new { message = mailed ? "Invitation emailed again." : "A new link was made, but the email could not be sent." });
    }

    // ---- what an invitation is ------------------------------------------------------------

    /// <summary>What an invitation is at <paramref name="now"/>: pending, accepted, revoked, or expired.</summary>
    internal static string StatusOf(Invitation invitation, DateTimeOffset now) =>
        invitation.Status == Invitation.Pending && invitation.ExpiresAt <= now ? "expired" : invitation.Status;

    internal static string NewToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    /// <summary>The form a link's token is kept in: its SHA-256, in hexadecimal.</summary>
    internal static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    internal static string Normalize(string email) => email.Trim().ToLowerInvariant();

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string Iso(DateTimeOffset at) => at.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static bool IsAddress(string? email) => email is { Length: <= 320 } && Address().IsMatch(email);

    /// <summary>Something before an at sign, and after it a name with a dot in it: what can be mailed, not a proof it can.</summary>
    [GeneratedRegex(@"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Address();

    private static IResult NotPending() =>
        Problems.Refuse(StatusCodes.Status409Conflict, "invitation_not_pending", "That invitation is not pending any more.");

    private static async Task<(Invitation? Invitation, IResult? Refusal)> FindAsync(AuthwayDbContext db, string id, bool track)
    {
        if (!Guid.TryParse(id, out var key))
        {
            return (null, Refuse("invalid_request", "The invitation id is not valid."));
        }

        var invitation = await (track ? db.Invitations : db.Invitations.AsNoTracking()).FirstOrDefaultAsync(i => i.Id == key);
        return invitation is null
            ? (null, Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "There is no such invitation."))
            : (invitation, null);
    }

    /// <summary>
    /// Mails the link, in the language the request asked for. A mail that cannot be sent does not undo
    /// the invitation — it can be sent again — but the answer says so.
    /// </summary>
    private static async Task<bool> TryMailAsync(IMailSender mail, Invitation invitation, string token, HttpContext context, IConfiguration configuration, ILoggerFactory logs)
    {
        try
        {
            var baseUrl = BootstrapConfig.UiAddress(context, configuration);
            var message = Messages.Render(
                "invitation",
                context.Request.Headers.AcceptLanguage.ToString(),
                new Dictionary<string, object?>
                {
                    ["link"] = $"{baseUrl}/invitation/accept?token={Uri.EscapeDataString(token)}",
                    ["inviterName"] = invitation.InviterName,
                    ["tenantName"] = AdminEndpoints.DefaultTenantName,
                    ["message"] = invitation.Message,
                });
            await mail.SendAsync(invitation.Email, message, context.RequestAborted);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            MailFailed(logs.CreateLogger("Authway.Invitations"), exception, invitation.Id);
            return false;
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "The invitation {Invitation} could not be mailed")]
    private static partial void MailFailed(ILogger logger, Exception exception, Guid invitation);

    private static async Task<Dictionary<string, object?>> ToJsonAsync(IOpenIddictApplicationManager applications, Invitation invitation, DateTimeOffset now)
    {
        var json = new Dictionary<string, object?>
        {
            ["id"] = invitation.Id.ToString(),
            ["tenant_id"] = AdminEndpoints.DefaultTenantId.ToString(),
            ["email"] = invitation.Email,
            ["status"] = StatusOf(invitation, now),
            ["inviter_id"] = null,
            ["inviter_name"] = invitation.InviterName,
            ["tenant_name"] = AdminEndpoints.DefaultTenantName,
            ["accepted_at"] = invitation.AcceptedAt is { } at ? Iso(at) : null,
            ["accepted_by"] = invitation.AcceptedBy?.ToString(),
            ["expires_at"] = Iso(invitation.ExpiresAt),
            ["created_at"] = Iso(invitation.CreatedAt),
            ["updated_at"] = Iso(invitation.UpdatedAt),
        };
        if (invitation.Message is not null)
        {
            json["message"] = invitation.Message;
        }

        if (invitation.ClientId is not null && await applications.FindByClientIdAsync(invitation.ClientId) is { } application)
        {
            json["client"] = await InvitationApp(applications, application, invitation.ClientId);
        }

        return json;
    }

    /// <summary>The application an invitation is for: what a screen needs to send the person on once they have an account.</summary>
    internal static async Task<Dictionary<string, object?>> InvitationApp(IOpenIddictApplicationManager applications, object application, string clientId)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        string Text(string key) => descriptor.Properties.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : string.Empty;

        var app = new Dictionary<string, object?> { ["client_id"] = clientId, ["name"] = descriptor.DisplayName ?? clientId };
        if (Text("initiate_login_uri") is { Length: > 0 } login)
        {
            app["initiate_login_uri"] = login;
        }

        if (Text("client_uri") is { Length: > 0 } home)
        {
            app["client_uri"] = home;
        }

        return app;
    }
}
