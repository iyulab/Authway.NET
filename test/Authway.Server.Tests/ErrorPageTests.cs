using System.Net;
using System.Net.Http.Json;

namespace Authway.Server.Tests;

/// <summary>Where an application is told to look for the parts of an installation, and where a request nobody can answer ends.</summary>
public abstract partial class ServerTests
{
    private static readonly string[] CodeAndRefresh = ["authorization_code", "refresh_token"];
    private static readonly string[] EverythingAsked = ["openid", "email", "profile", "offline_access"];

    [Fact]
    public async Task TheBootstrapDocument_SaysWhereTheIssuerTheApiAndTheScreensAre()
    {
        var plain = await BodyOfAsync(await server.Client.GetAsync(new Uri("/.well-known/authway-config", UriKind.Relative)));
        var origin = server.Client.BaseAddress!.GetLeftPart(UriPartial.Authority);
        Assert.Equal(origin, plain.GetProperty("issuer").GetString());
        Assert.Equal(origin, plain.GetProperty("api_url").GetString());
        Assert.Equal(origin, plain.GetProperty("auth_ui").GetString());
        Assert.False(string.IsNullOrEmpty(plain.GetProperty("version").GetString()));

        var elsewhere = server.CreateClientWith(new Dictionary<string, string?> { ["Authway:Ui:BaseUrl"] = "https://login.example.test/" });
        var moved = await BodyOfAsync(await elsewhere.GetAsync(new Uri("/.well-known/authway-config", UriKind.Relative)));
        Assert.Equal("https://login.example.test", moved.GetProperty("auth_ui").GetString());
    }

    [Fact]
    public async Task ARequestThatCannotBeAnsweredToTheApplication_EndsAtTheErrorPage_NotAtTheAddressItNamed()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var browser = server.CreateClient(followRedirects: false);
        var tokens = await ExchangeAsync(application, await SignInAndGetCodeAsync(browser, application, address, pkce), pkce.Verifier);
        var idToken = tokens.Body.GetProperty("id_token").GetString()!;

        var logout = await browser.GetAsync(new Uri($"/connect/logout?id_token_hint={Uri.EscapeDataString(idToken)}&post_logout_redirect_uri={Uri.EscapeDataString("https://elsewhere.invalid/back")}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Contains("/error?error=invalid_request", logout.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.DoesNotContain("elsewhere.invalid", logout.Headers.Location.OriginalString, StringComparison.Ordinal);

        var authorize = await browser.GetAsync(new Uri($"/connect/authorize?client_id={application}&response_type=code&redirect_uri={Uri.EscapeDataString("https://elsewhere.invalid/cb")}&scope=openid&code_challenge={Pkce.New().Challenge}&code_challenge_method=S256", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        Assert.Contains("/error?error=invalid_request", authorize.Headers.Location!.OriginalString, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnApplicationThatStopsSkippingConsent_AsksAgain_WhatWasAllowedWhileItDidNotAskIsWithdrawn()
    {
        var admin = AdminClient(AdminKey);
        var created = (await RegisterClientAsync(admin, new
        {
            name = "was the tenants own",
            @public = true,
            skip_consent = true,
            redirect_uris = new[] { Callback },
            allowed_origins = new[] { new Uri(Callback).GetLeftPart(UriPartial.Authority) },
            grant_types = CodeAndRefresh,
            scopes = EverythingAsked,
        })).GetProperty("client");
        var clientId = created.GetProperty("client_id").GetString()!;
        var (_, address) = await NewPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        await SignInAndGetCodeAsync(browser, clientId, address, Pkce.New());

        var silent = await browser.GetAsync(new Uri(AuthorizeUrl(clientId, Pkce.New().Challenge, prompt: "none"), UriKind.Relative));
        Assert.Contains("code=", silent.Headers.Location!.OriginalString, StringComparison.Ordinal);

        var turned = await admin.PutAsJsonAsync(ClientAt(created.GetProperty("id").GetString()!), new { skip_consent = false });
        Assert.Equal(HttpStatusCode.OK, turned.StatusCode);

        var asked = await browser.GetAsync(new Uri(AuthorizeUrl(clientId, Pkce.New().Challenge, prompt: "none"), UriKind.Relative));
        Assert.Contains("error=consent_required", asked.Headers.Location!.OriginalString, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDiscoveryDocument_AdvertisesTheClaimsOfTheContract_AndIsReadableFromAnyPage()
    {
        var response = await server.Client.GetAsync(new Uri("/.well-known/openid-configuration", UriKind.Relative));
        var document = await BodyOfAsync(response);

        Assert.Contains("*", response.Headers.GetValues("Access-Control-Allow-Origin"));
        var claims = document.GetProperty("claims_supported").EnumerateArray().Select(c => c.GetString()).ToList();
        foreach (var claim in new[] { "sub", "tenant_id", "email", "email_verified", "name", "auth_time", "amr" })
        {
            Assert.Contains(claim, claims);
        }

        // Only what a client can use is listed: a secret in the form, no HTTP Basic, no signed assertion.
        Assert.Equal(["client_secret_post"], document.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(m => m.GetString()));
        Assert.False(document.TryGetProperty("token_endpoint_auth_signing_alg_values_supported", out _));
        Assert.False(document.GetProperty("frontchannel_logout_supported").GetBoolean());
        Assert.False(document.GetProperty("request_uri_parameter_supported").GetBoolean());
        var alias = await server.Client.GetAsync(new Uri("/.well-known/oauth-authorization-server", UriKind.Relative));
        Assert.Equal(await response.Content.ReadAsStringAsync(), await alias.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task TheTokens_SayWhichTenantThePersonBelongsTo_AndHowTheySignedIn()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var tokens = await ExchangeAsync(application, await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce), pkce.Verifier);

        foreach (var name in new[] { "access_token", "id_token" })
        {
            var claims = Claims(tokens.Body.GetProperty(name).GetString()!);
            Assert.Equal("00000000-0000-0000-0000-000000000001", claims.GetProperty("tenant_id").GetString());
            Assert.Contains("pwd", claims.GetProperty("amr").EnumerateArray().Select(m => m.GetString()));
        }
    }
}
