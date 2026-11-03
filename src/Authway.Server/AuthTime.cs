using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace Authway.Server;

/// <summary>
/// When the person last proved who they are. The session cookie is renewed as it
/// is used, which moves the time it was issued, so the moment of the sign-in is
/// kept in the session itself: it is what <c>max_age</c> is measured against,
/// what <c>prompt=login</c> must be newer than, and what the ID token's
/// <c>auth_time</c> says.
/// </summary>
internal static class AuthTime
{
    private const string Key = "authway:auth_time";

    /// <summary>The session of a person who has just signed in.</summary>
    public static AuthenticationProperties Of(bool persistent, DateTimeOffset now) => new()
    {
        IsPersistent = persistent,
        Items = { [Key] = now.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) },
    };

    /// <summary>When the person signed in, or null when there is no session.</summary>
    public static DateTimeOffset? Of(AuthenticateResult session)
    {
        if (!session.Succeeded)
        {
            return null;
        }

        return session.Properties!.Items.TryGetValue(Key, out var value) && long.TryParse(value, CultureInfo.InvariantCulture, out var milliseconds)
            ? DateTimeOffset.FromUnixTimeMilliseconds(milliseconds)
            : session.Properties.IssuedUtc;
    }
}
