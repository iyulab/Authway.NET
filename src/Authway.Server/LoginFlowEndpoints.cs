using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Authway.Server;

/// <summary>
/// The API the sign-in screen talks to (the contract's <c>login-flows</c>). The
/// screen knows a flow only by its opaque id: it asks what to show, and hands
/// the person's answer back to the same flow.
/// </summary>
internal static class LoginFlowEndpoints
{
    /// <summary>The password form, named as the contract's <c>sign_in_methods</c> names it.</summary>
    public const string PasswordMethod = "email";

    /// <summary>What this server can offer a person for signing in: the password form so far.</summary>
    private static readonly string[] SignInMethods = [PasswordMethod];

    public static void Map(IEndpointRouteBuilder app)
    {
        var flows = app.MapGroup("/api/v1/login-flows");
        flows.MapGet("/{flow}", GetAsync);
        flows.MapPost("/{flow}/password", SubmitPasswordAsync).RefuseCrossSite();
    }

    private static async Task<IResult> GetAsync(string flow, HttpContext context, IFlowStore store)
    {
        var state = store.Find(flow, FlowKind.Login, out var open);
        if (state != FlowState.Open)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        // A session that began since the flow did (in another tab) is all the flow was waiting for.
        // One that was there before it is not: the application asked to be shown a sign-in.
        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (AuthTime.Of(session) is { } signedInAt && signedInAt >= open!.OpenedAt)
        {
            store.Complete(flow);
            return Results.Json(new Redirect("redirect", open!.ContinueTo), LoginFlowJson.Options);
        }

        return Results.Json(new LoginForm(
            "form",
            open!.Id,
            open.ClientName,
            open.RequestedScope,
            new LoginFormClient(open.ClientId, SignInMethods),
            HintsOf(open)), LoginFlowJson.Options);
    }

    private static async Task<IResult> SubmitPasswordAsync(
        string flow,
        PasswordRequest? body,
        IFlowStore store,
        UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn,
        IPasswordHasher<ApplicationUser> hasher,
        TimeProvider time)
    {
        var state = store.Find(flow, FlowKind.Login, out var open);
        if (state != FlowState.Open)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        if (string.IsNullOrWhiteSpace(body?.Email) || string.IsNullOrEmpty(body.Password))
        {
            return Problems.Refuse(StatusCodes.Status400BadRequest, "invalid_request", "Enter an email address and a password.");
        }

        // An unknown address and a wrong password get the same answer, so the answer does not say who has an account.
        // Nor does the time it takes: an address with no account gets a password check of the same cost.
        var user = await users.FindByEmailAsync(body.Email.Trim());
        if (user is null)
        {
            hasher.VerifyHashedPassword(NoAccount, NoAccountHash.Value(hasher), body.Password);
            return InvalidCredentials();
        }

        var result = await signIn.CheckPasswordSignInAsync(user, body.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return InvalidCredentials();
        }

        await signIn.SignInAsync(user, AuthTime.Of(body.Remember, time.GetUtcNow()));
        store.Complete(flow);
        return Results.Json(new Redirect("redirect", open!.ContinueTo), LoginFlowJson.Options);
    }

    private static readonly ApplicationUser NoAccount = new();

    /// <summary>A hash of a password nobody knows, made with the hasher the accounts use so that checking against it costs the same.</summary>
    private static class NoAccountHash
    {
        private static string? _hash;

        public static string Value(IPasswordHasher<ApplicationUser> hasher) =>
            _hash ??= hasher.HashPassword(NoAccount, Guid.NewGuid().ToString("N"));
    }

    private static IResult InvalidCredentials() =>
        Problems.Refuse(StatusCodes.Status401Unauthorized, "invalid_credentials", "The email address or the password is not right.");

    private static LoginFormHints? HintsOf(Flow flow)
    {
        var hints = flow.Hints;
        if (hints.SignInMethod is null && hints.LoginHint is null && hints.UiLocales.Count == 0)
        {
            return null;
        }

        return new LoginFormHints(hints.SignInMethod, hints.LoginHint, hints.UiLocales.Count == 0 ? null : hints.UiLocales);
    }

    private sealed record PasswordRequest(string? Email, string? Password, bool Remember);

    private sealed record Redirect(string Next, string RedirectTo);

    private sealed record LoginFormClient(string ClientId, IReadOnlyList<string> SignInMethods);

    private sealed record LoginFormHints(string? SignInMethod, string? LoginHint, IReadOnlyList<string>? UiLocales);

    private sealed record LoginForm(
        string Next,
        string Flow,
        string ClientName,
        IReadOnlyList<string> RequestedScope,
        LoginFormClient Client,
        LoginFormHints? Hints);
}
