using Microsoft.AspNetCore.Identity;

namespace Authway.Data;

/// <summary>
/// An account that signs in to this installation. The address is the account's
/// user name as well: Authway signs people in by their address.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>
{
    /// <summary>What the person is called, as they gave it.</summary>
    public string? DisplayName { get; set; }

    /// <summary>When the account was made.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
