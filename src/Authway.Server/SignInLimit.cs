using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Authway.Server;

/// <summary>
/// How often one network address may answer a sign-in. Every request counts, and the ceiling
/// (<c>Authway:Limits:SignInPerMinute</c>, 60) is far above what a person, or an office signing in
/// behind one address, makes; the guesser is held by the account lock-out and by the flow, which
/// ends after a few wrong answers. Past it the answer is <c>429 too_many_requests</c>.
/// </summary>
internal static class SignInLimit
{
    public const string Policy = "sign-in";

    private const int DefaultPerMinute = 60;

    public static void Add(IServiceCollection services) => services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.OnRejected = async (context, cancellation) =>
        {
            var seconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var after) ? (int)Math.Ceiling(after.TotalSeconds) : 60;
            context.HttpContext.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            await Problems.Refuse(StatusCodes.Status429TooManyRequests, "too_many_requests", "Too many attempts. Try again later.", seconds)
                .ExecuteAsync(context.HttpContext);
        };

        options.AddPolicy(Policy, context =>
        {
            // Read when the address is first seen, from the configuration the host runs with.
            var limit = context.RequestServices.GetRequiredService<IConfiguration>().GetValue("Authway:Limits:SignInPerMinute", DefaultPerMinute);
            return RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
        });
    });
}
