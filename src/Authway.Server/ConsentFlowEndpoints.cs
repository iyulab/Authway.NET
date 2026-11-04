using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The API the consent screen talks to (the contract's <c>consent-flows</c>):
/// an application asks for access to a person's account, the person says what
/// they allow — or that they allow nothing — and the browser goes on.
/// </summary>
internal static class ConsentFlowEndpoints
{
    public static void Map(IEndpointRouteBuilder app)
    {
        var flows = app.MapGroup("/api/v1/consent-flows");
        flows.MapGet("/{flow}", GetAsync);
        flows.MapPost("/{flow}/accept", AcceptAsync).RefuseCrossSite();
        flows.MapPost("/{flow}/reject", RejectAsync).RefuseCrossSite();
    }

    private static async Task<IResult> GetAsync(string flow, HttpContext context, IFlowStore store, UserManager<ApplicationUser> users)
    {
        var (refusal, open, user) = await ResolveAsync(flow, context, store, users);
        if (refusal is not null)
        {
            return refusal;
        }

        return Results.Json(
            new ConsentForm("form", open!.Id, open.ClientName, open.RequestedScope, new ConsentUser(user!.Email!, user.DisplayName)),
            LoginFlowJson.Options);
    }

    private static async Task<IResult> AcceptAsync(
        string flow,
        AcceptRequest? body,
        HttpContext context,
        IFlowStore store,
        UserManager<ApplicationUser> users,
        IOpenIddictApplicationManager applications,
        Consents consents)
    {
        var (refusal, open, user) = await ResolveAsync(flow, context, store, users);
        if (refusal is not null)
        {
            return refusal;
        }

        // The person may allow less than was asked for, never more; and without `openid` there is no sign-in to speak of.
        var granted = (body?.GrantScope ?? []).Distinct().ToList();
        if (granted.Count == 0 || granted.Except(open!.RequestedScope).Any() || (open.RequestedScope.Contains(Scopes.OpenId) && !granted.Contains(Scopes.OpenId)))
        {
            return Problems.Refuse(StatusCodes.Status400BadRequest, "invalid_request", "Choose what to allow from what the application asked for.");
        }

        var application = await applications.FindByClientIdAsync(open.ClientId)
            ?? throw new InvalidOperationException("The application details cannot be found.");
        if (!await applications.IsOnAsync(application))
        {
            store.Complete(flow);
            return Problems.Refuse(StatusCodes.Status403Forbidden, "unauthorized_client", "This application is turned off.");
        }

        var consent = await consents.GrantAsync(user!.Id.ToString(), application, granted, keep: body!.Remember);

        // The request comes back with the answer that was just given, and with nothing else to go by.
        store.Complete(flow);
        return Results.Json(new Redirect("redirect", QueryHelpers.AddQueryString(open.ContinueTo, Consents.AnsweredParameter, consent.AuthorizationId)), LoginFlowJson.Options);
    }

    private static async Task<IResult> RejectAsync(string flow, HttpContext context, IFlowStore store, UserManager<ApplicationUser> users)
    {
        var (refusal, open, _) = await ResolveAsync(flow, context, store, users);
        if (refusal is not null)
        {
            return refusal;
        }

        store.Complete(flow);
        return Results.Json(new Redirect("redirect", open!.RejectTo ?? open.ContinueTo), LoginFlowJson.Options);
    }

    /// <summary>The flow, and the person it is asking: only the person who was sent to answer it may.</summary>
    private static async Task<(IResult? Refusal, Flow? Flow, ApplicationUser? User)> ResolveAsync(
        string flow,
        HttpContext context,
        IFlowStore store,
        UserManager<ApplicationUser> users)
    {
        var state = store.Find(flow, FlowKind.Consent, out var open);
        if (state != FlowState.Open)
        {
            return (state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow(), null, null);
        }

        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var user = session.Succeeded ? await users.GetUserAsync(session.Principal!) : null;
        if (user is null || user.Id.ToString() != open!.Subject)
        {
            return (Problems.UnknownFlow(), null, null);
        }

        return (null, open, user);
    }

    private sealed record AcceptRequest(IReadOnlyList<string>? GrantScope, bool Remember);

    private sealed record Redirect(string Next, string RedirectTo);

    private sealed record ConsentUser(string Email, string? Name);

    private sealed record ConsentForm(string Next, string Flow, string ClientName, IReadOnlyList<string> RequestedScope, ConsentUser User);
}
