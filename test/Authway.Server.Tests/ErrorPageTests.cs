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
}
