using Authway.Data;
using Authway.Server.Flows;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// Signing out, as the sign-out screen asks for it (the contract's
/// <c>logout-flows</c>): the person's session ends and what they were given in
/// it stops working, then the browser goes on to where the application asked.
/// </summary>
internal static class LogoutFlowEndpoints
{
    public static void Map(IEndpointRouteBuilder app) =>
        app.MapPost("/api/v1/logout-flows/{flow}", CompleteAsync).RefuseCrossSite();

    private static async Task<IResult> CompleteAsync(
        string flow,
        HttpContext context,
        IFlowStore store,
        SignInManager<ApplicationUser> signIn,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations,
        AuditTrail audit)
    {
        var state = store.Find(flow, FlowKind.Logout, out var open);
        if (state != FlowState.Open)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var subject = session.Principal?.FindFirst(Claims.Subject)?.Value;

        // An application that says whom it is signing out (the ID token it holds) does not get to sign out someone
        // else who happens to be using this browser: if that is not the person signed in here, nothing of theirs ends.
        if (open!.Subject is not null && open.Subject != subject)
        {
            store.Complete(flow);
            return Results.Json(new { next = "redirect", redirect_to = open.ContinueTo }, LoginFlowJson.Options);
        }

        await signIn.SignOutAsync();
        if (subject is not null)
        {
            // What the person was given in the session — across every application — stops working with it.
            await tokens.RevokeBySubjectAsync(subject);
            await authorizations.RevokeBySubjectAsync(subject);
            await audit.RecordAsync(context, AuditActions.UserLogout, "user", subject,
                actorId: Guid.TryParse(subject, out var person) ? person : null, actorEmail: session.Principal?.FindFirst(Claims.Email)?.Value);
        }

        store.Complete(flow);
        return Results.Json(new { next = "redirect", redirect_to = open.ContinueTo }, LoginFlowJson.Options);
    }
}
