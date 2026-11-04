using System.Globalization;
using Authway.Data;
using Microsoft.EntityFrameworkCore;
using static Authway.Server.AdminRequest;

namespace Authway.Server;

/// <summary>
/// Reading the audit log (<c>/api/v1/audit/*</c>): what was done, by whom, and whether it worked. A filter that
/// is not well formed is refused, never ignored. Entries are only ever read here, and removed once they are
/// past their retention.
/// </summary>
internal static class AuditEndpoints
{
    private const int DefaultPerPage = 100;
    private const int MostPerPage = 1000;
    private const int MostActivity = 500;
    private const int MostSecurityEvents = 100;
    private const int LeastRetentionDays = 30;
    private const int MostRetentionDays = 36500;

    /// <summary>How long an entry is kept when the installation does not say (<c>Authway:Audit:RetentionDays</c>).</summary>
    public const int DefaultRetentionDays = 365;

    private static readonly string[] TimeFormats = ["yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"];

    public static void Map(RouteGroupBuilder admin)
    {
        admin.MapGet("/audit/logs", QueryAsync);
        admin.MapDelete("/audit/logs/purge", PurgeAsync);
        admin.MapGet("/audit/logs/{id}", GetAsync);
        admin.MapGet("/audit/users/{userId}/activity", ActivityAsync);
        admin.MapGet("/audit/security", SecurityAsync);
        admin.MapGet("/audit/summary", SummaryAsync);
        admin.MapGet("/audit/actions", Actions);
    }

    private static async Task<IResult> QueryAsync(HttpContext context, AuthwayDbContext db)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var query = context.Request.Query;
        var entries = db.AuditLogs.AsNoTracking().AsQueryable();

        if (query["actor_id"].ToString() is { Length: > 0 } actor)
        {
            if (!Guid.TryParse(actor, out var actorId))
            {
                return Invalid("actor_id must be a user id", "actor_id");
            }

            entries = entries.Where(e => e.ActorId == actorId);
        }

        if (query["action"].ToString() is { Length: > 0 } action)
        {
            if (!AuditActions.IsKnown(action))
            {
                return Invalid($"unknown action \"{action}\"; GET /api/v1/audit/actions lists them", "action");
            }

            entries = entries.Where(e => e.Action == action);
        }

        if (query["severity"].ToString() is { Length: > 0 } severity)
        {
            if (!AuditActions.IsKnownSeverity(severity))
            {
                return Invalid("severity must be one of info, warning, error, critical", "severity");
            }

            entries = entries.Where(e => e.Severity == severity);
        }

        switch (query["success"].ToString())
        {
            case "":
                break;
            case "true":
                entries = entries.Where(e => e.Success);
                break;
            case "false":
                entries = entries.Where(e => !e.Success);
                break;
            default:
                return Invalid("success must be true or false", "success");
        }

        if (query["resource_type"].ToString() is { Length: > 0 } resourceType)
        {
            entries = entries.Where(e => e.ResourceType == resourceType);
        }

        if (query["resource_id"].ToString() is { Length: > 0 } resourceId)
        {
            entries = entries.Where(e => e.ResourceId == resourceId);
        }

        foreach (var name in new[] { "start_time", "end_time" })
        {
            if (query[name].ToString() is not { Length: > 0 } raw)
            {
                continue;
            }

            if (!DateTimeOffset.TryParseExact(raw, TimeFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var at))
            {
                return Invalid($"{name} must be an RFC 3339 time", name);
            }

            at = at.ToUniversalTime();
            entries = name == "start_time" ? entries.Where(e => e.CreatedAt >= at) : entries.Where(e => e.CreatedAt <= at);
        }

        var (limit, badLimit) = Number(query["limit"], DefaultPerPage, 1, MostPerPage, "limit");
        if (badLimit is not null)
        {
            return badLimit;
        }

        var (offset, badOffset) = Number(query["offset"], 0, 0, int.MaxValue, "offset");
        if (badOffset is not null)
        {
            return badOffset;
        }

        var total = await entries.CountAsync();
        var page = await entries.OrderByDescending(e => e.CreatedAt).ThenByDescending(e => e.Id).Skip(offset).Take(limit).ToListAsync();
        return Results.Json(new Dictionary<string, object>
        {
            ["logs"] = page.Select(ToJson).ToList(),
            ["total"] = total,
            ["limit"] = limit,
            ["offset"] = offset,
        });
    }

    private static async Task<IResult> GetAsync(string id, AuthwayDbContext db)
    {
        if (!Guid.TryParse(id, out var entryId))
        {
            return Invalid("invalid audit log ID", "id");
        }

        var entry = await db.AuditLogs.AsNoTracking().FirstOrDefaultAsync(e => e.Id == entryId);
        return entry is null
            ? Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "audit log not found")
            : Results.Json(new { log = ToJson(entry) });
    }

    private static async Task<IResult> ActivityAsync(HttpContext context, string userId, AuthwayDbContext db)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        if (!Guid.TryParse(userId, out var actorId))
        {
            return Invalid("invalid user ID", "userId");
        }

        var (limit, bad) = Number(context.Request.Query["limit"], 50, 1, MostActivity, "limit");
        if (bad is not null)
        {
            return bad;
        }

        var entries = await db.AuditLogs.AsNoTracking().Where(e => e.ActorId == actorId).OrderByDescending(e => e.CreatedAt).Take(limit).ToListAsync();
        return Results.Json(new { logs = entries.Select(ToJson).ToList() });
    }

    private static async Task<IResult> SecurityAsync(HttpContext context, AuthwayDbContext db, TimeProvider time)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var (hours, bad) = Number(context.Request.Query["hours"], 24, 1, 168, "hours");
        if (bad is not null)
        {
            return bad;
        }

        var since = time.GetUtcNow().AddHours(-hours);
        var entries = await db.AuditLogs.AsNoTracking()
            .Where(e => e.CreatedAt >= since && AuditActions.Security.Contains(e.Action))
            .OrderByDescending(e => e.CreatedAt).Take(MostSecurityEvents).ToListAsync();
        return Results.Json(new Dictionary<string, object> { ["logs"] = entries.Select(ToJson).ToList(), ["hours"] = hours });
    }

    private static async Task<IResult> SummaryAsync(HttpContext context, AuthwayDbContext db, TimeProvider time)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var now = time.GetUtcNow();
        var day = now.AddHours(-24);
        var week = now.AddDays(-7);
        var month = now.AddDays(-30);
        var entries = db.AuditLogs.AsNoTracking();

        return Results.Json(new
        {
            summary = new Dictionary<string, int>
            {
                ["total_24h"] = await entries.CountAsync(e => e.CreatedAt >= day),
                ["total_7d"] = await entries.CountAsync(e => e.CreatedAt >= week),
                ["total_30d"] = await entries.CountAsync(e => e.CreatedAt >= month),
                ["security_events"] = await entries.CountAsync(e => e.CreatedAt >= day && AuditActions.Security.Contains(e.Action)),
                ["failed_operations"] = await entries.CountAsync(e => e.CreatedAt >= day && !e.Success),
            },
        });
    }

    private static IResult Actions() => Results.Json(new
    {
        actions = AuditActions.All.Select(a => new { action = a.Action, description = a.Description }).ToList(),
        severities = AuditActions.Severities.Select(s => new { severity = s.Severity, description = s.Description }).ToList(),
    });

    private static async Task<IResult> PurgeAsync(HttpContext context, AuthwayDbContext db, IConfiguration configuration, TimeProvider time)
    {
        if (TenantRefusal(context, null) is { } wrongTenant)
        {
            return wrongTenant;
        }

        // Without retention_days, the entries past the installation's own retention go.
        var (named, badDays) = Number(context.Request.Query["retention_days"], 0, LeastRetentionDays, MostRetentionDays, "retention_days", unnamed: 0);
        if (badDays is not null)
        {
            return badDays;
        }

        var days = named == 0 ? RetentionDays(configuration) : named;
        var deleted = await PurgeOlderThanAsync(db, time, days);
        return Results.Json(new Dictionary<string, object>
        {
            ["deleted"] = deleted,
            ["retention_days"] = days,
            ["message"] = $"Deleted {deleted} audit log entries older than {days} days.",
        });
    }

    /// <summary>How long entries are kept: the installation's setting, never less than the least a purge accepts.</summary>
    internal static int RetentionDays(IConfiguration configuration) =>
        Math.Clamp(configuration.GetValue("Authway:Audit:RetentionDays", DefaultRetentionDays), LeastRetentionDays, MostRetentionDays);

    /// <summary>Deletes the entries older than <paramref name="days"/> days and says how many there were.</summary>
    internal static async Task<int> PurgeOlderThanAsync(AuthwayDbContext db, TimeProvider time, int days)
    {
        var cutoff = time.GetUtcNow().AddDays(-days);
        return await db.AuditLogs.Where(e => e.CreatedAt < cutoff).ExecuteDeleteAsync();
    }

    private static IResult Invalid(string message, string field) => Refuse("invalid_request", message, field);

    /// <summary>A whole number in a range, or the default when the query does not carry it, or a refusal.</summary>
    private static (int Value, IResult? Refusal) Number(string? raw, int fallback, int least, int most, string name, int? unnamed = null)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return (unnamed ?? fallback, null);
        }

        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n >= least && n <= most
            ? (n, null)
            : (0, Invalid($"{name} must be an integer between {least} and {most}", name));
    }

    private static Dictionary<string, object?> ToJson(AuditLog e) => new()
    {
        ["id"] = e.Id.ToString(),
        ["tenant_id"] = e.TenantId.ToString(),
        ["actor_id"] = e.ActorId?.ToString(),
        ["actor_email"] = e.ActorEmail ?? string.Empty,
        ["actor_type"] = e.ActorType,
        ["action"] = e.Action,
        ["severity"] = e.Severity,
        ["resource_type"] = e.ResourceType ?? string.Empty,
        ["resource_id"] = e.ResourceId ?? string.Empty,
        ["ip_address"] = e.IpAddress ?? string.Empty,
        ["user_agent"] = e.UserAgent ?? string.Empty,
        ["details"] = e.Details,
        ["success"] = e.Success,
        ["error_msg"] = e.ErrorMsg ?? string.Empty,
        ["created_at"] = e.CreatedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
    };
}
