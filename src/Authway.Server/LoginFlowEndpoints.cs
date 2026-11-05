using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

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
        flows.MapGet("/{flow}/social/{provider}", SocialAsync);
        flows.MapPost("/{flow}/password", SubmitPasswordAsync).RefuseCrossSite().RequireRateLimiting(SignInLimit.Policy);
    }

    private static async Task<IResult> GetAsync(string flow, HttpContext context, IFlowStore store, IOpenIddictApplicationManager applications)
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
            await ClientEndpoints.LogoOfAsync(applications, open.ClientId),
            open.RequestedScope,
            new LoginFormClient(open.ClientId, SignInMethods),
            CapabilitiesEndpoint.InviteOnlySignup,
            HintsOf(open)), LoginFlowJson.Options);
    }

    /// <summary>
    /// Signing in with another provider starts as a page navigation. None is offered here, so the flow it was
    /// started on ends and the browser goes back to the application, which is told the request cannot be met.
    /// </summary>
    private static IResult SocialAsync(string flow, IFlowStore store)
    {
        var state = store.Find(flow, FlowKind.Login, out var open);
        if (state != FlowState.Open)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        store.Complete(flow);
        return Results.Redirect(open!.RejectTo ?? open.ContinueTo);
    }

    private static async Task<IResult> SubmitPasswordAsync(
        string flow,
        PasswordRequest? body,
        HttpContext context,
        IFlowStore store,
        UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn,
        IPasswordHasher<ApplicationUser> hasher,
        TimeProvider time,
        IOpenIddictApplicationManager applications,
        AuditTrail audit)
    {
        // Submits of one flow that overlap are taken one after the other: the second finds what the first did.
        using var hold = await store.HoldAsync(flow);
        var state = store.Find(flow, FlowKind.Login, out var open);

        // The sign-in screen stays up while the browser follows the redirect, so a flow that was signed in is
        // answered again for the person it signed in, once they prove who they are again: a second click is the same sign-in.
        string? signedInAs = null;
        var again = state == FlowState.Expired && store.TryFindSignedIn(flow, out open, out signedInAs);
        if (state != FlowState.Open && !again)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        // A sign-in already under way when an administrator turned the application off does not get through.
        if (await applications.FindByClientIdAsync(open!.ClientId) is { } application && !await applications.IsOnAsync(application))
        {
            store.Complete(flow);
            return Problems.Refuse(StatusCodes.Status403Forbidden, "unauthorized_client", "This application is turned off.");
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
            store.Fail(flow);
            await audit.RecordAsync(context, AuditActions.UserLoginFailed, "user", null, success: false, severity: AuditTrail.Warning,
                error: "unknown address", actorEmail: body.Email.Trim());
            return InvalidCredentials();
        }

        // A flow that was signed in belongs to the person it signed in. A password for anyone else's account is
        // not checked, so the answer cannot say whether it was right: it is refused as a wrong one is.
        if (again && user.Id.ToString() != signedInAs)
        {
            hasher.VerifyHashedPassword(NoAccount, NoAccountHash.Value(hasher), body.Password);
            store.Fail(flow);
            await audit.RecordAsync(context, AuditActions.UserLoginFailed, "user", user.Id.ToString(), success: false, severity: AuditTrail.Warning,
                error: "flow of another user", actorId: user.Id, actorEmail: user.Email);
            return InvalidCredentials();
        }

        var result = await signIn.CheckPasswordSignInAsync(user, body.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            store.Fail(flow);
            await audit.RecordAsync(context, AuditActions.UserLoginFailed, "user", user.Id.ToString(), success: false, severity: AuditTrail.Warning,
                error: result.IsLockedOut ? "locked out" : "wrong password", actorId: user.Id, actorEmail: user.Email);
            return InvalidCredentials();
        }

        // The right password is refused for an account an administrator has suspended; a wrong one says nothing of it.
        if (user.Suspended)
        {
            await audit.RecordAsync(context, AuditActions.UserLoginFailed, "user", user.Id.ToString(), success: false, severity: AuditTrail.Warning,
                error: "suspended", actorId: user.Id, actorEmail: user.Email);
            return Problems.Refuse(StatusCodes.Status403Forbidden, "account_suspended", "This account has been suspended.");
        }

        if (again)
        {
            // The person the flow signed in, proved again; the sign-in itself, and its record, are not repeated.
            return Results.Json(new Redirect("redirect", open!.ContinueTo), LoginFlowJson.Options);
        }

        await signIn.SignInAsync(user, AuthTime.Of(body.Remember, time.GetUtcNow()));
        store.SignedIn(flow, user.Id.ToString());
        await audit.RecordAsync(context, AuditActions.UserLogin, "user", user.Id.ToString(), actorId: user.Id, actorEmail: user.Email);
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
        string? ClientLogoUri,
        IReadOnlyList<string> RequestedScope,
        LoginFormClient Client,
        string SignupMode,
        LoginFormHints? Hints);
}
