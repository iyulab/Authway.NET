namespace Authway.Server;

/// <summary>
/// What this installation offers (the contract's <c>capabilities</c>), so that the screens show only
/// what works here. This server is one tenant, signs people in by password and has none of the
/// extras the contract lists, and says so: the document is the same one every implementation
/// answers, with its own values.
/// </summary>
internal static class CapabilitiesEndpoint
{
    /// <summary>
    /// How a person comes to have an account here: by an invitation, and no other way (the contract's
    /// <c>SignupMode</c>). The sign-in screen is told so, to say it to someone who cannot sign in.
    /// </summary>
    internal const string InviteOnlySignup = "invite_only";

    private static readonly string[] SignupModes = [InviteOnlySignup];

    public static void Map(IEndpointRouteBuilder app) => app.MapGet("/api/v1/capabilities", () => Results.Json(
        new Dictionary<string, object>
        {
            ["multi_tenant"] = false,
            ["providers"] = Array.Empty<string>(),
            ["magic_link"] = false,
            ["mfa"] = Array.Empty<string>(),
            ["signup_modes"] = SignupModes,
            ["account_deletion"] = false,
            ["custom_claims"] = false,
            ["backchannel_logout"] = false,
            ["token_introspection"] = false,
            ["device_authorization"] = false,
            ["terms_acceptance"] = false,
            ["token_exchange"] = false,
            ["approval_requests"] = false,
            ["passkeys"] = false,
            ["breached_password_check"] = false,
            ["webhooks"] = false,
            ["client_provider_apps"] = false,
            ["ciba"] = false,
        }));
}
