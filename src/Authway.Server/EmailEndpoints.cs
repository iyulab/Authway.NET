using Authway.Data;
using Authway.Server.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// The links a person is mailed to prove their address and to choose a new password. A request for a
/// message answers the same whether or not the address has an account, whether it is verified already
/// and whether the message could be handed over — any difference would tell a caller which addresses
/// are registered — and the message is sent after the answer has gone (<see cref="MailQueue"/>).
/// </summary>
internal static partial class EmailEndpoints
{
    internal const string VerificationRequested = "If the address has an unverified account, a verification link has been sent";
    internal const string PasswordResetRequested = "If the address has an account, a password reset link has been sent";

    /// <summary>How many messages of one kind an account is sent in <see cref="MailWindow"/>, however many callers ask.</summary>
    private const int MailsPerAccount = 3;

    private static readonly TimeSpan MailWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan VerificationLifetime = TimeSpan.FromHours(6);
    private static readonly TimeSpan ResetLifetime = TimeSpan.FromHours(1);

    public static void Map(IEndpointRouteBuilder app)
    {
        var email = app.MapGroup("/api/v1/email");
        email.MapPost("/send-verification", SendVerificationAsync).RequireRateLimiting(SignInLimit.MailPolicy);
        email.MapGet("/verify", VerifyAsync);
        email.MapPost("/forgot-password", ForgotPasswordAsync).RequireRateLimiting(SignInLimit.MailPolicy);
        email.MapGet("/verify-reset-token", VerifyResetTokenAsync).RequireRateLimiting(SignInLimit.Policy);
        email.MapPost("/reset-password", ResetPasswordAsync).RequireRateLimiting(SignInLimit.Policy);
    }

    private static Task<IResult> SendVerificationAsync(HttpContext context, IOpenIddictApplicationManager applications, MailQueue queue, IConfiguration configuration, IHostEnvironment environment) =>
        RequestAsync(context, applications, queue, configuration, environment, EmailToken.Verification);

    private static Task<IResult> ForgotPasswordAsync(HttpContext context, IOpenIddictApplicationManager applications, MailQueue queue, IConfiguration configuration, IHostEnvironment environment) =>
        RequestAsync(context, applications, queue, configuration, environment, EmailToken.PasswordReset);

    /// <summary>
    /// Asks for a link to be mailed to the account at the address, when there is one a link is of use to. The call
    /// answers at once and does the rest after the answer (looking the account up, counting what it was sent, making
    /// the link, mailing it), so that how long the answer takes does not say whether the address has an account.
    /// </summary>
    private static async Task<IResult> RequestAsync(HttpContext context, IOpenIddictApplicationManager applications, MailQueue queue, IConfiguration configuration, IHostEnvironment environment, string purpose)
    {
        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        var address = String(body!.Value, "email")?.Trim();
        if (!InvitationEndpoints.IsAddress(address))
        {
            return Refuse("invalid_request", "A valid email address is required.", "email");
        }

        // This installation is one tenant, so an application is not needed to tell which account is meant;
        // one that is named has to exist, as everywhere an application is named.
        var clientId = String(body.Value, "client_id");
        if (!string.IsNullOrEmpty(clientId) && await applications.FindByClientIdAsync(clientId) is null)
        {
            return Refuse("unknown_client", "client_id names no registered application", "client_id");
        }

        var baseUrl = LinkBase(context, configuration, environment);
        var locale = Messages.Negotiate(context.Request.Headers.AcceptLanguage.ToString());
        queue.Enqueue(
            purpose == EmailToken.Verification ? "verification" : "reset",
            (services, cancellation) => MailLinkAsync(services, address!, purpose, baseUrl, locale, cancellation));
        // A request that names an application also says how people come to have an account, whether or not this
        // address does (see the contract's MailRequested): that is what lets the screen tell someone who gets no
        // mail that the service is for invited people.
        var message = purpose == EmailToken.Verification ? VerificationRequested : PasswordResetRequested;
        return string.IsNullOrEmpty(clientId)
            ? Results.Json(new { message })
            : Results.Json(new { message, signup_mode = CapabilitiesEndpoint.InviteOnlySignup });
    }

    /// <summary>
    /// Where the screens a link opens are. A link that goes to the address the request was made at would go wherever
    /// the caller said the server is (anyone can ask for a link for anyone's address, with a Host header of their
    /// choosing), so outside development the address has to be configured (<c>Authway:Ui:BaseUrl</c>), and without it
    /// no link is mailed.
    /// </summary>
    private static string? LinkBase(HttpContext context, IConfiguration configuration, IHostEnvironment environment) =>
        configuration["Authway:Ui:BaseUrl"] is { Length: > 0 } configured ? configured.TrimEnd('/')
        : environment.IsDevelopment() ? BootstrapConfig.Origin(context)
        : null;

    private static async Task MailLinkAsync(IServiceProvider services, string address, string purpose, string? baseUrl, string locale, CancellationToken cancellation)
    {
        var db = services.GetRequiredService<AuthwayDbContext>();
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var account = await users.FindByEmailAsync(address);

        // Nothing is sent to an account that is suspended (it could not use the link), to one whose address is
        // verified already, or to one that has been sent several lately.
        if (account is null || account.Suspended || (purpose == EmailToken.Verification && account.EmailConfirmed))
        {
            return;
        }

        if (baseUrl is null)
        {
            NoLinkBase(services.GetRequiredService<ILoggerFactory>().CreateLogger("Authway.Mail"));
            return;
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var since = now - MailWindow;
        if (await db.EmailTokens.CountAsync(t => t.UserId == account.Id && t.Purpose == purpose && t.CreatedAt > since, cancellation) >= MailsPerAccount)
        {
            return;
        }

        var token = InvitationEndpoints.NewToken();
        db.EmailTokens.Add(new EmailToken
        {
            Id = Guid.NewGuid(),
            UserId = account.Id,
            Purpose = purpose,
            TokenHash = InvitationEndpoints.Hash(token),
            CreatedAt = now,
            ExpiresAt = now + (purpose == EmailToken.Verification ? VerificationLifetime : ResetLifetime),
        });
        await db.SaveChangesAsync(cancellation);

        var (name, path) = purpose == EmailToken.Verification ? ("verification", "verify-email") : ("reset", "reset-password");
        await services.GetRequiredService<IMailSender>().SendAsync(
            account.Email!,
            Messages.Render(name, locale, new Dictionary<string, object?> { ["link"] = $"{baseUrl}/{path}?token={Uri.EscapeDataString(token)}" }),
            cancellation);
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "No link is mailed: Authway:Ui:BaseUrl is not set, and a link must not go to the address a request names")]
    private static partial void NoLinkBase(ILogger logger);

    /// <summary>The reset links of an account that can still be used, spent: a password chosen makes the ones asked for before it moot.</summary>
    internal static Task SpendResetLinksAsync(AuthwayDbContext db, Guid userId, DateTimeOffset now) =>
        db.EmailTokens
            .Where(t => t.UserId == userId && t.Purpose == EmailToken.PasswordReset && t.UsedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, now));

    private static async Task<IResult> VerifyAsync(HttpContext context, AuthwayDbContext db, UserManager<ApplicationUser> users, TimeProvider time, AuditTrail audit)
    {
        if (context.Request.Query["token"].ToString() is not { Length: > 0 } token)
        {
            return Refuse("invalid_request", "Token is required");
        }

        var link = await FindAsync(db, token, EmailToken.Verification);
        if (link is null)
        {
            return Problems.Refuse(StatusCodes.Status404NotFound, "invalid_token", "Invalid or expired verification token");
        }

        var now = time.GetUtcNow();
        if (link.ExpiresAt <= now)
        {
            return Refuse("token_expired", "Verification token has expired");
        }

        var account = await users.FindByIdAsync(link.UserId.ToString());
        if (account is null)
        {
            return Problems.Refuse(StatusCodes.Status404NotFound, "invalid_token", "Invalid or expired verification token");
        }

        // The link may be followed again (a mail client that opens links ahead of the person is no reason
        // to refuse the person); it only ever does the one thing.
        if (!account.EmailConfirmed)
        {
            account.EmailConfirmed = true;
            var saved = await users.UpdateAsync(account);
            if (!saved.Succeeded)
            {
                return Problems.Refuse(StatusCodes.Status500InternalServerError, "internal_error", "Failed to update user status");
            }

            await audit.RecordAsync(context, AuditActions.UserEmailVerified, "user", account.Id.ToString(), actorId: account.Id, actorEmail: account.Email);
        }

        await db.EmailTokens.Where(t => t.Id == link.Id && t.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, now));
        return Results.Json(new { message = "Email verified successfully" });
    }

    private static async Task<IResult> VerifyResetTokenAsync(HttpContext context, AuthwayDbContext db, UserManager<ApplicationUser> users, TimeProvider time)
    {
        if (context.Request.Query["token"].ToString() is not { Length: > 0 } token)
        {
            return Refuse("invalid_request", "Token is required");
        }

        var (_, _, refusal) = await ResolveResetAsync(db, users, token, time.GetUtcNow());
        if (refusal is not null)
        {
            return refusal;
        }

        return Results.Json(new Dictionary<string, object>
        {
            ["valid"] = true,
            ["message"] = "Reset token is valid",
            ["password_min_length"] = InvitationPublicEndpoints.PasswordMinLength,
        });
    }

    private static async Task<IResult> ResetPasswordAsync(
        HttpContext context,
        AuthwayDbContext db,
        UserManager<ApplicationUser> users,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations,
        TimeProvider time,
        AuditTrail audit)
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

        var password = String(body.Value, "new_password") ?? string.Empty;
        var now = time.GetUtcNow();
        var (link, account, refusal) = await ResolveResetAsync(db, users, token, now);
        if (refusal is not null)
        {
            return refusal;
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

        // The link is spent first, in one statement that only an unused, unexpired one satisfies, so that two
        // answers to the same link choose one password.
        var claimed = await db.EmailTokens
            .Where(t => t.Id == link!.Id && t.UsedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, now));
        if (claimed == 0)
        {
            return Refuse("token_expired", "Reset token is invalid or has expired");
        }

        var changed = await users.ResetPasswordAsync(account!, await users.GeneratePasswordResetTokenAsync(account!), password);
        if (!changed.Succeeded)
        {
            // The link was not used up by a password that was not chosen.
            await db.EmailTokens.Where(t => t.Id == link!.Id).ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, (DateTimeOffset?)null));
            return Refuse("password_too_short", changed.Errors.FirstOrDefault()?.Description ?? "The password cannot be used.", "new_password");
        }

        // Every other link asked for before this password was chosen is moot.
        await SpendResetLinksAsync(db, account!.Id, now);

        // The link reached the account's address: using it proves the address as a verification mail would.
        if (!account.EmailConfirmed)
        {
            account.EmailConfirmed = true;
            await users.UpdateAsync(account);
        }

        // Whoever held the account's sessions may not know the new password: they end (the security stamp changed
        // with the password), and what the account was given is revoked.
        var subject = account.Id.ToString();
        await tokens.RevokeBySubjectAsync(subject);
        await authorizations.RevokeBySubjectAsync(subject);
        await audit.RecordAsync(context, AuditActions.UserPasswordReset, "user", subject, actorId: account.Id, actorEmail: account.Email);
        return Results.Json(new { message = "Password reset successfully" });
    }

    /// <summary>
    /// The reset link and the account it is for, or the refusal to give: not a link we sent, one that is spent
    /// or expired, or one for an account an administrator has suspended since (it proves the address, so it is
    /// told why, as signing in is).
    /// </summary>
    private static async Task<(EmailToken? Link, ApplicationUser? Account, IResult? Refusal)> ResolveResetAsync(AuthwayDbContext db, UserManager<ApplicationUser> users, string token, DateTimeOffset now)
    {
        var link = await FindAsync(db, token, EmailToken.PasswordReset);
        if (link is null)
        {
            return (null, null, Refuse("invalid_token", "Invalid or expired reset token"));
        }

        if (link.UsedAt is not null || link.ExpiresAt <= now)
        {
            return (null, null, Refuse("token_expired", "Reset token is invalid or has expired"));
        }

        var account = await users.FindByIdAsync(link.UserId.ToString());
        if (account is null)
        {
            return (null, null, Refuse("invalid_token", "Invalid or expired reset token"));
        }

        return account.Suspended
            ? (null, null, Problems.Refuse(StatusCodes.Status403Forbidden, "account_suspended", "This account is suspended"))
            : (link, account, null);
    }

    private static Task<EmailToken?> FindAsync(AuthwayDbContext db, string token, string purpose)
    {
        var hash = InvitationEndpoints.Hash(token);
        return db.EmailTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash && t.Purpose == purpose);
    }
}
