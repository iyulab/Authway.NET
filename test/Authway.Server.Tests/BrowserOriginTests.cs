using System.Net;

namespace Authway.Server.Tests;

/// <summary>
/// An application's pages run on their own origin. What describes the installation and the token endpoint are open to
/// a page on any origin, the routes a person calls with their own token to the origins clients registered, and the
/// administration API to none.
/// </summary>
public abstract partial class ServerTests
{
    private static readonly (string Path, string Method)[] PersonRoutes =
    [
        ("/api/v1/profile/me", "GET"),
        ("/api/v1/profile/me", "DELETE"),
        ("/api/v1/logout", "POST"),
        ("/api/v1/users/password", "POST"),
    ];

    private static readonly string[] AdminRoutes = ["/api/v1/clients", "/api/v1/users", "/api/v1/invitations"];

    private static readonly string[] Descriptions = ["/.well-known/authway-config", "/api/v1/capabilities", "/.well-known/openid-configuration"];

    private static HttpRequestMessage FromOrigin(HttpMethod method, string path, string origin, string? preflightFor = null)
    {
        var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
        request.Headers.Add("Origin", origin);
        if (preflightFor is not null)
        {
            request.Headers.Add("Access-Control-Request-Method", preflightFor);
            request.Headers.Add("Access-Control-Request-Headers", "authorization");
        }

        return request;
    }

    private static string? AllowedOrigin(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values) ? values.Single() : null;

    [Fact]
    public async Task WhatDescribesTheInstallation_AndTheTokenEndpoint_AreOpenToAPageOnAnyOrigin()
    {
        const string stranger = "https://stranger.example.net";
        foreach (var path in Descriptions)
        {
            using var response = await server.Client.SendAsync(FromOrigin(HttpMethod.Get, path, stranger));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("*", AllowedOrigin(response));
            Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"), path);
        }

        using var preflight = await server.Client.SendAsync(FromOrigin(HttpMethod.Options, "/connect/token", stranger, preflightFor: "POST"));
        Assert.True((int)preflight.StatusCode < 300);
        Assert.Equal("*", AllowedOrigin(preflight));

        // A refusal is readable too, or the page could not tell why.
        using var refused = FromOrigin(HttpMethod.Post, "/connect/token", stranger);
        refused.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["code"] = "not-a-code", ["client_id"] = "nobody" });
        using var answered = await server.Client.SendAsync(refused);
        Assert.Equal(HttpStatusCode.BadRequest, answered.StatusCode);
        Assert.Equal("*", AllowedOrigin(answered));
    }

    [Fact]
    public async Task ARegisteredOrigin_CallsTheRoutesAPersonCalls_AndNoOtherDoes()
    {
        var admin = AdminClient(AdminKey);
        var origin = $"https://app-{Guid.NewGuid():N}.example.org";
        await RegisterClientAsync(admin, new
        {
            tenant_id = TenantId,
            name = $"origins-{Guid.NewGuid():N}"[..20],
            @public = true,
            redirect_uris = new[] { $"{origin}/callback" },
            allowed_origins = new[] { origin },
            grant_types = AuthorizationCode,
            scopes = Openid,
        });

        foreach (var (path, method) in PersonRoutes)
        {
            using var response = await server.Client.SendAsync(FromOrigin(HttpMethod.Options, path, origin, method));
            Assert.Equal(origin, AllowedOrigin(response));
            Assert.Contains("authorization", response.Headers.GetValues("Access-Control-Allow-Headers").Single(), StringComparison.OrdinalIgnoreCase);
            // The token is the credential: cookies are not sent from an application's origin.
            Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"), path);
        }

        // The answer carries the header as well, or the page could not read it: here a refusal, since no token is presented.
        using var unsigned = await server.Client.SendAsync(FromOrigin(HttpMethod.Get, "/api/v1/profile/me", origin));
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        Assert.Equal(origin, AllowedOrigin(unsigned));

        // An origin no client registered is not admitted; neither is a registered one to the administration API.
        using var stranger = await server.Client.SendAsync(FromOrigin(HttpMethod.Options, "/api/v1/profile/me", "https://stranger.example.net", "GET"));
        Assert.Null(AllowedOrigin(stranger));
        foreach (var path in AdminRoutes)
        {
            using var response = await server.Client.SendAsync(FromOrigin(HttpMethod.Options, path, origin, "GET"));
            Assert.Null(AllowedOrigin(response));
        }
    }
}
