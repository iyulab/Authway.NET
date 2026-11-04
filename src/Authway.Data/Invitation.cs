namespace Authway.Data;

/// <summary>
/// An invitation to sign up: onboarding here is by invitation only. The link that was mailed carries
/// a token; only its hash is kept, so a copy of the database holds no usable link.
/// </summary>
public class Invitation
{
    public const string Pending = "pending";
    public const string Accepted = "accepted";
    public const string Revoked = "revoked";

    public Guid Id { get; set; }

    /// <summary>The address invited, as it was written.</summary>
    public required string Email { get; set; }

    /// <summary>The address in the one form addresses are compared in.</summary>
    public required string NormalizedEmail { get; set; }

    /// <summary>What the person who invited said to the person invited.</summary>
    public string? Message { get; set; }

    /// <summary>Who invited, as the invitation names them.</summary>
    public required string InviterName { get; set; }

    /// <summary>The OAuth <c>client_id</c> of the application the invitation is for, when it is for one.</summary>
    public string? ClientId { get; set; }

    /// <summary>The SHA-256 of the link's token, in hexadecimal; the previous link's when the invitation was resent.</summary>
    public required string TokenHash { get; set; }

    /// <summary><see cref="Pending"/>, <see cref="Accepted"/> or <see cref="Revoked"/>; one that is pending past <see cref="ExpiresAt"/> is expired.</summary>
    public required string Status { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public DateTimeOffset? AcceptedAt { get; set; }

    /// <summary>The account the invitation became.</summary>
    public Guid? AcceptedBy { get; set; }
}
