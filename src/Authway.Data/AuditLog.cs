namespace Authway.Data;

/// <summary>
/// One entry of the audit log: who did what to what, when, and whether it worked. An entry is written
/// just after the change it records, and never changed after.
/// </summary>
public class AuditLog
{
    public Guid Id { get; set; }

    /// <summary>The tenant the entry belongs to; this edition has one.</summary>
    public Guid TenantId { get; set; }

    /// <summary>The account that acted, when a person did. A call with the administration key has none.</summary>
    public Guid? ActorId { get; set; }

    public string? ActorEmail { get; set; }

    /// <summary>What kind of actor: <c>user</c>, <c>api_key</c> or <c>system</c>.</summary>
    public required string ActorType { get; set; }

    /// <summary>What happened, one of the actions <c>GET /api/v1/audit/actions</c> lists.</summary>
    public required string Action { get; set; }

    /// <summary><c>info</c>, <c>warning</c>, <c>error</c> or <c>critical</c>.</summary>
    public required string Severity { get; set; }

    public string? ResourceType { get; set; }

    public string? ResourceId { get; set; }

    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    /// <summary>JSON text recorded with the event.</summary>
    public string Details { get; set; } = "{}";

    public bool Success { get; set; } = true;

    /// <summary>Why the action failed; empty on success.</summary>
    public string? ErrorMsg { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
