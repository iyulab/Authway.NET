namespace Authway.Data;

/// <summary>
/// The link in a mail that proves an address: one to verify the address, one to choose a new password.
/// Only the SHA-256 of the link's token is kept, so a copy of the database holds no usable link. The
/// tokens are kept here rather than derived from the account's security stamp because a link has to
/// outlive things that rotate the stamp: a link sent before an administrator suspended the account is
/// still the owner of the address speaking, and is told why it is refused.
/// </summary>
public class EmailToken
{
    /// <summary>The link confirms the account's address.</summary>
    public const string Verification = "verification";

    /// <summary>The link lets the account's owner choose a new password.</summary>
    public const string PasswordReset = "password_reset";

    public Guid Id { get; set; }

    /// <summary>The account the link was sent for.</summary>
    public Guid UserId { get; set; }

    /// <summary><see cref="Verification"/> or <see cref="PasswordReset"/>.</summary>
    public required string Purpose { get; set; }

    /// <summary>The SHA-256 of the link's token, in hexadecimal.</summary>
    public required string TokenHash { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the link did what it is for; a link that has is spent.</summary>
    public DateTimeOffset? UsedAt { get; set; }
}
