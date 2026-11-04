using System.Text.Json;
using Authway.Data;

namespace Authway.Server;

/// <summary>What an audit entry can say happened. Every action listed is one the server records.</summary>
internal static class AuditActions
{
    public const string UserCreated = "user.created";
    public const string UserUpdated = "user.updated";
    public const string UserDeleted = "user.deleted";
    public const string UserLogin = "user.login";
    public const string UserLoginFailed = "user.login_failed";
    public const string UserLogout = "user.logout";
    public const string UserSuspended = "user.suspended";
    public const string UserReactivated = "user.reactivated";
    public const string ClientCreated = "client.created";
    public const string ClientUpdated = "client.updated";
    public const string ClientDeleted = "client.deleted";

    public static readonly IReadOnlyList<(string Action, string Description)> All =
    [
        (UserCreated, "User account created"),
        (UserUpdated, "User account updated"),
        (UserDeleted, "User account deleted"),
        (UserLogin, "User signed in"),
        (UserLoginFailed, "Sign-in refused"),
        (UserLogout, "User signed out"),
        (UserSuspended, "User account suspended by an administrator"),
        (UserReactivated, "User account suspension lifted by an administrator"),
        (ClientCreated, "OAuth client created"),
        (ClientUpdated, "OAuth client updated"),
        (ClientDeleted, "OAuth client deleted"),
    ];

    /// <summary>What an administrator looking for trouble wants first: refused authentication, and accounts that stopped existing.</summary>
    public static readonly string[] Security = [UserLoginFailed, UserDeleted];

    public static readonly IReadOnlyList<(string Severity, string Description)> Severities =
    [
        (AuditTrail.Info, "Informational events"),
        (AuditTrail.Warning, "Warning events"),
        (AuditTrail.Error, "Error events"),
        (AuditTrail.Critical, "Critical security events"),
    ];

    public static bool IsKnown(string action) => All.Any(a => a.Action == action);

    public static bool IsKnownSeverity(string severity) => Severities.Any(s => s.Severity == severity);
}

/// <summary>
/// Writes the audit log. An entry is written just after the change it records, in a scope of its own, so
/// that it is not lost with a change that failed and does not disturb the one in progress; a failure to
/// write it is logged and never fails what it records.
/// </summary>
internal sealed partial class AuditTrail(IServiceScopeFactory scopes, TimeProvider time, ILogger<AuditTrail> logger)
{
    public const string Info = "info";
    public const string Warning = "warning";
    public const string Error = "error";
    public const string Critical = "critical";

    /// <summary>The key of <see cref="HttpContext.Items"/> in which a caller who passed the administration key is marked.</summary>
    public const string ActorItem = "authway.audit.actor";

    // The widest each bounded column is (AuthwayDbContext). Some of what is recorded is what a caller typed — the
    // address of a sign-in that was refused — and an entry that does not fit would not be written at all.
    private const int MostEmail = 320;
    private const int MostActorType = 50;
    private const int MostResourceType = 100;
    private const int MostResourceId = 255;
    private const int MostIpAddress = 45;
    private const int MostUserAgent = 512;

    /// <summary>Records <paramref name="action"/> on a resource, as the caller of <paramref name="context"/> did it.</summary>
    public Task RecordAsync(
        HttpContext? context,
        string action,
        string resourceType,
        string? resourceId,
        bool success = true,
        string severity = Info,
        string? error = null,
        Guid? actorId = null,
        string? actorEmail = null,
        IReadOnlyDictionary<string, object?>? details = null)
    {
        var actorType = context?.Items[ActorItem] as string ?? (actorId is null ? "system" : "user");
        return WriteAsync(new AuditLog
        {
            Id = Guid.NewGuid(),
            TenantId = AdminEndpoints.DefaultTenantId,
            ActorId = actorId,
            ActorEmail = Truncate(actorEmail, MostEmail),
            ActorType = Truncate(actorType, MostActorType)!,
            Action = action,
            Severity = severity,
            ResourceType = Truncate(resourceType, MostResourceType),
            ResourceId = Truncate(resourceId, MostResourceId),
            IpAddress = Truncate(context?.Connection.RemoteIpAddress?.ToString(), MostIpAddress),
            UserAgent = Truncate(context?.Request.Headers.UserAgent.ToString(), MostUserAgent),
            Details = details is { Count: > 0 } ? JsonSerializer.Serialize(details) : "{}",
            Success = success,
            ErrorMsg = error,
            CreatedAt = time.GetUtcNow(),
        });
    }

    private async Task WriteAsync(AuditLog entry)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
            db.AuditLogs.Add(entry);
            await db.SaveChangesAsync();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            WriteFailed(logger, exception, entry.Action);
        }
    }

    private static string? Truncate(string? value, int most) =>
        string.IsNullOrEmpty(value) ? null : value.Length <= most ? value : value[..most];

    [LoggerMessage(Level = LogLevel.Error, Message = "The audit entry for {Action} could not be written")]
    private static partial void WriteFailed(ILogger logger, Exception exception, string action);
}

/// <summary>
/// Removes the entries that are past their retention (<c>Authway:Audit:RetentionDays</c>, a year unless the
/// installation says otherwise), once when the server has started and then every day.
/// </summary>
internal sealed partial class AuditRetention(IServiceScopeFactory scopes, IConfiguration configuration, TimeProvider time, ILogger<AuditRetention> logger) : BackgroundService
{
    private static readonly TimeSpan Every = TimeSpan.FromDays(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // Not while the server is still starting: the schema is brought up to date first.
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            using var timer = new PeriodicTimer(Every);
            do
            {
                await PurgeAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
            // The server is stopping.
        }
    }

    private async Task PurgeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<Authway.Data.AuthwayDbContext>();
            var days = AuditEndpoints.RetentionDays(configuration);
            var deleted = await AuditEndpoints.PurgeOlderThanAsync(db, time, days);
            if (deleted > 0)
            {
                Purged(logger, deleted, days);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            PurgeFailed(logger, exception);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Audit entries purged: {Deleted} older than {Days} days")]
    private static partial void Purged(ILogger logger, int deleted, int days);

    [LoggerMessage(Level = LogLevel.Error, Message = "The audit entries past their retention could not be removed")]
    private static partial void PurgeFailed(ILogger logger, Exception exception);
}
