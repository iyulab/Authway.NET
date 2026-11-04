using System.Globalization;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// The people who have an account (<c>/api/v1/users</c>), for an administrator: who they are, what they are
/// called, and removing one. What this installation does not keep — an avatar address, suspending an
/// account — is refused with the code the contract names, not accepted and ignored.
/// </summary>
internal static class UserEndpoints
{
    private const int MostPerPage = 100;
    private const int DefaultPerPage = 20;

    public static void Map(RouteGroupBuilder admin)
    {
        admin.MapGet("/users", ListAsync);
        admin.MapPost("/users/search", SearchAsync);
        admin.MapGet("/users/{id}", GetAsync);
        admin.MapPut("/users/{id}", UpdateAsync);
        admin.MapDelete("/users/{id}", DeleteAsync);
    }

    private static async Task<IResult> ListAsync(HttpContext context, UserManager<ApplicationUser> users)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var query = context.Request.Query;
        var limit = Math.Clamp(int.TryParse(query["limit"], CultureInfo.InvariantCulture, out var l) ? l : DefaultPerPage, 1, MostPerPage);
        var offset = Math.Max(int.TryParse(query["offset"], CultureInfo.InvariantCulture, out var o) ? o : 0, 0);

        var total = await users.Users.CountAsync();
        var page = await users.Users.AsNoTracking().OrderByDescending(u => u.CreatedAt).ThenBy(u => u.Id).Skip(offset).Take(limit).ToListAsync();
        return Results.Json(new Dictionary<string, object> { ["users"] = page.Select(ToJson).ToList(), ["total"] = total, ["limit"] = limit, ["offset"] = offset });
    }

    private static async Task<IResult> SearchAsync(HttpContext context, UserManager<ApplicationUser> users)
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

        if (String(body.Value, "email")?.Trim() is not { Length: > 0 } email || !email.Contains('@', StringComparison.Ordinal))
        {
            return Refuse("invalid_request", "A valid email address is required.", "email");
        }

        // Addresses are compared without regard to case; Identity keeps them normalized for exactly that.
        var found = await users.FindByEmailAsync(email);
        return Results.Json(new { users = found is null ? [] : new[] { ToJson(found) } });
    }

    private static async Task<IResult> GetAsync(string id, UserManager<ApplicationUser> users)
    {
        var (user, refusal) = await FindAsync(users, id);
        return refusal ?? Results.Json(new { user = ToJson(user!) });
    }

    private static async Task<IResult> UpdateAsync(string id, HttpContext context, UserManager<ApplicationUser> users, AuditTrail audit)
    {
        var (user, notFound) = await FindAsync(users, id);
        if (notFound is not null)
        {
            return notFound;
        }

        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        if (String(body!.Value, "avatar_url") is { Length: > 0 })
        {
            return Refuse("invalid_request", "This installation keeps no avatar address.", "avatar_url");
        }

        if (Bool(body.Value, "active") is false)
        {
            return Refuse("invalid_request", "Suspending an account is not offered by this installation.", "active");
        }

        if (body.Value.TryGetProperty("name", out var name))
        {
            if (name.ValueKind != System.Text.Json.JsonValueKind.String)
            {
                return Refuse("invalid_request", "A name is a string.", "name");
            }

            // An empty name clears it.
            user!.DisplayName = string.IsNullOrWhiteSpace(name.GetString()) ? null : name.GetString()!.Trim();
            var updated = await users.UpdateAsync(user);
            if (!updated.Succeeded)
            {
                return Refuse("invalid_request", updated.Errors.First().Description, "name");
            }
        }

        await audit.RecordAsync(context, AuditActions.UserUpdated, "user", id);
        return Results.Json(new { message = "User updated.", user = ToJson(user!) });
    }

    private static async Task<IResult> DeleteAsync(
        string id,
        HttpContext context,
        UserManager<ApplicationUser> users,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations,
        AuditTrail audit)
    {
        var (user, notFound) = await FindAsync(users, id);
        if (notFound is not null)
        {
            return notFound;
        }

        // What the person was given stops working with the account.
        var subject = user!.Id.ToString();
        await tokens.RevokeBySubjectAsync(subject);
        await authorizations.RevokeBySubjectAsync(subject);
        var deleted = await users.DeleteAsync(user);
        if (!deleted.Succeeded)
        {
            return Problems.Refuse(StatusCodes.Status500InternalServerError, "internal_server_error", "The user could not be deleted.");
        }

        await audit.RecordAsync(context, AuditActions.UserDeleted, "user", id, severity: AuditTrail.Warning);
        return Results.Json(new { message = "User deleted." });
    }

    private static async Task<(ApplicationUser? User, IResult? Refusal)> FindAsync(UserManager<ApplicationUser> users, string id)
    {
        if (!Guid.TryParse(id, out _))
        {
            return (null, Refuse("invalid_request", "The user id is not valid."));
        }

        var user = await users.FindByIdAsync(id);
        return user is null
            ? (null, Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "There is no such user."))
            : (user, null);
    }

    private static Dictionary<string, object?> ToJson(ApplicationUser user)
    {
        var json = new Dictionary<string, object?>
        {
            ["id"] = user.Id.ToString(),
            ["tenant_id"] = AdminEndpoints.DefaultTenantId.ToString(),
            ["email"] = user.Email,
            ["email_verified"] = user.EmailConfirmed,
            ["active"] = !(user.LockoutEnd is { } lockedUntil && lockedUntil > DateTimeOffset.UtcNow),
            ["connections"] = Array.Empty<string>(),
            ["totp_enabled"] = false,
            ["last_login_at"] = null,
            ["created_at"] = user.CreatedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        };
        if (user.DisplayName is not null)
        {
            json["name"] = user.DisplayName;
        }

        return json;
    }
}
