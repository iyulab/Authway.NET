using Authway.Data;
using Microsoft.AspNetCore.Identity;

namespace Authway.Server;

/// <summary>Whether an account may be used at all.</summary>
internal static class Accounts
{
    /// <summary>
    /// An account that has been suspended, or is locked out after too many wrong passwords, is nobody a token
    /// is issued for or answered about: what it was given stops being good.
    /// </summary>
    public static async Task<bool> CanBeUsedAsync(this UserManager<ApplicationUser> users, ApplicationUser user) =>
        !user.Suspended && !await users.IsLockedOutAsync(user);
}
