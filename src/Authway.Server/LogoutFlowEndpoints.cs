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
        app.MapPost("/api/v1/logout-flows/{flow}", CompleteAsync);

    private static async Task<IResult> CompleteAsync(
        string flow,
        HttpContext context,
        IFlowStore store,
        SignInManager<ApplicationUser> signIn,
        IOpenIddictTokenManager tokens,
        IOpenIddictAuthorizationManager authorizations)
    {
        var state = store.Find(flow, FlowKind.Logout, out var open);
        if (state != FlowState.Open)
        {
            return state == FlowState.Unknown ? Problems.UnknownFlow() : Problems.ExpiredFlow();
        }

        var session = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var subject = session.Principal?.FindFirst(Claims.Subject)?.Value;

        await signIn.SignOutAsync();
        if (subject is not null)
        {
            // What the person was given in the session — across every application — stops working with it.
            await tokens.RevokeBySubjectAsync(subject);
            await authorizations.RevokeBySubjectAsync(subject);
        }

        store.Complete(flow);
        return Results.Json(new { next = "redirect", redirect_to = open!.ContinueTo }, LoginFlowJson.Options);
    }
}
