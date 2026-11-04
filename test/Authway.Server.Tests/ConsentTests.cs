using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server.Tests;

/// <summary>An application that is not the account holder's own asks before it gets in.</summary>
public abstract partial class ServerTests
{
    private static readonly string[] Everything = ["openid", "email", "profile", "offline_access"];
    private static readonly string[] SignInAndEmail = ["openid", "email"];
    private static readonly string[] SignInOnly = ["openid"];
    private static readonly string[] MoreThanAsked = ["openid", "address"];
    private static readonly string[] NoSignIn = ["email"];

    [Fact]
    public async Task AnApplicationThatAsks_IsAskedAbout_AndTheAnswerIsKept()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();

        var flow = await ConsentFlowAsync(browser, application, address, pkce);

        var screen = await browser.GetAsync(new Uri($"/api/v1/consent-flows/{flow}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, screen.StatusCode);
        using var form = JsonDocument.Parse(await screen.Content.ReadAsStringAsync());
        Assert.Equal("form", form.RootElement.GetProperty("next").GetString());
        Assert.Equal(flow, form.RootElement.GetProperty("flow").GetString());
        Assert.Equal("Application under test", form.RootElement.GetProperty("client_name").GetString());
        Assert.Contains("profile", form.RootElement.GetProperty("requested_scope").EnumerateArray().Select(s => s.GetString()));
        Assert.Equal(address, form.RootElement.GetProperty("user").GetProperty("email").GetString());
        Assert.Equal("Person Under Test", form.RootElement.GetProperty("user").GetProperty("name").GetString());

        var code = await AcceptAsync(browser, flow, Everything, remember: true);
        var tokens = await ExchangeAsync(application, code, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        // The next request is not asked about: the answer was kept.
        var later = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge), UriKind.Relative));
        Assert.StartsWith(Callback, later.Headers.Location!.OriginalString);

        // Unless the application says it wants to be sure.
        var sure = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge, prompt: "consent"), UriKind.Relative));
        Assert.StartsWith("/consent?flow=", sure.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task APersonMayAllowLessThanWasAskedFor_ButNotMore()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var flow = await ConsentFlowAsync(browser, application, address, pkce);

        var tooMuch = await browser.PostAsJsonAsync(new Uri($"/api/v1/consent-flows/{flow}/accept", UriKind.Relative), new { grant_scope = MoreThanAsked, remember = true });
        Assert.Equal(HttpStatusCode.BadRequest, tooMuch.StatusCode);
        var noSignIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/consent-flows/{flow}/accept", UriKind.Relative), new { grant_scope = NoSignIn, remember = true });
        Assert.Equal(HttpStatusCode.BadRequest, noSignIn.StatusCode);

        var code = await AcceptAsync(browser, flow, SignInAndEmail, remember: false);
        var tokens = await ExchangeAsync(application, code, pkce.Verifier);
        var identity = Claims(tokens.Body.GetProperty("id_token").GetString()!);
        Assert.Equal(address, identity.GetProperty("email").GetString());
        Assert.False(identity.TryGetProperty("name", out _), "the name was not allowed");
        Assert.False(tokens.Body.TryGetProperty("refresh_token", out _), "offline access was not allowed");
    }

    [Fact]
    public async Task AnAnswerThePersonDidNotAskToKeep_IsNotKept()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        var flow = await ConsentFlowAsync(browser, application, address, Pkce.New());
        await AcceptAsync(browser, flow, Everything, remember: false);

        using var scope = server.Services.CreateScope();
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var id = await applications.GetIdAsync((await applications.FindByClientIdAsync(application))!);
        var kept = await authorizations.FindAsync(null, id, Statuses.Valid, AuthorizationTypes.Permanent, default).CountAsync();
        Assert.Equal(0, kept);
    }

    [Fact]
    public async Task SayingNo_SendsTheApplicationBackWithAccessDenied()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        var flow = await ConsentFlowAsync(browser, application, address, Pkce.New());

        var no = await browser.PostAsync(new Uri($"/api/v1/consent-flows/{flow}/reject", UriKind.Relative), null);

        Assert.Equal(HttpStatusCode.OK, no.StatusCode);
        using var next = JsonDocument.Parse(await no.Content.ReadAsStringAsync());
        Assert.Equal("redirect", next.RootElement.GetProperty("next").GetString());
        var destination = new Uri(next.RootElement.GetProperty("redirect_to").GetString()!);
        Assert.StartsWith(Callback, destination.OriginalString);
        var query = HttpUtility.ParseQueryString(destination.Query);
        Assert.Equal("access_denied", query["error"]);
        Assert.Equal("state-123", query["state"]);
        Assert.Null(query["code"]);

        Assert.Equal(HttpStatusCode.Gone, (await browser.PostAsync(new Uri($"/api/v1/consent-flows/{flow}/reject", UriKind.Relative), null)).StatusCode);
    }

    [Fact]
    public async Task WhenTheApplicationAsksNotToAsk_NoConsentIsAnErrorBackToIt()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        await SignInAsync(browser, application, address);

        var response = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge, prompt: "none"), UriKind.Relative));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(Callback, response.Headers.Location!.OriginalString);
        Assert.Equal("consent_required", HttpUtility.ParseQueryString(response.Headers.Location.Query)["error"]);
    }

    [Fact]
    public async Task OnlyThePersonWhoWasAsked_CanAnswer()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        var browser = server.CreateClient(followRedirects: false);
        var flow = await ConsentFlowAsync(browser, application, address, Pkce.New());

        var stranger = server.CreateClient(followRedirects: false);
        var withoutSession = await stranger.PostAsJsonAsync(new Uri($"/api/v1/consent-flows/{flow}/accept", UriKind.Relative), new { grant_scope = SignInOnly, remember = true });
        Assert.Equal(HttpStatusCode.BadRequest, withoutSession.StatusCode);

        var (_, otherAddress) = await RegisterApplicationAndPersonAsync(ConsentTypes.Explicit);
        await SignInAsync(stranger, application, otherAddress);
        var asSomeoneElse = await stranger.PostAsync(new Uri($"/api/v1/consent-flows/{flow}/reject", UriKind.Relative), null);
        Assert.Equal(HttpStatusCode.BadRequest, asSomeoneElse.StatusCode);

        // The flow was not spent by the attempts.
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(new Uri($"/api/v1/consent-flows/{flow}", UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task ARequestTheBrowserSaysCameFromAnotherSite_IsNotTheScreenAsking()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);

        using var forged = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative))
        {
            Content = JsonContent.Create(new { email = address, password = Password }),
        };
        forged.Headers.Add("Sec-Fetch-Site", "cross-site");
        var refused = await browser.SendAsync(forged);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        using var body = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        Assert.Equal("forbidden", body.RootElement.GetProperty("code").GetString());

        // From the screen itself it works, and the refused attempt signed nobody in.
        using var own = new HttpRequestMessage(HttpMethod.Post, new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative))
        {
            Content = JsonContent.Create(new { email = address, password = Password }),
        };
        own.Headers.Add("Sec-Fetch-Site", "same-origin");
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(own)).StatusCode);
    }

    [Fact]
    public async Task AnApplicationCannotSignOutSomeoneElse_WhoIsUsingTheBrowser()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var (otherApplication, otherAddress) = await RegisterApplicationAndPersonAsync();
        var otherPkce = Pkce.New();
        var otherCode = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), otherApplication, otherAddress, otherPkce);
        var othersIdToken = (await ExchangeAsync(otherApplication, otherCode, otherPkce.Verifier)).Body.GetProperty("id_token").GetString()!;

        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(browser, application, address, pkce);
        var tokens = await ExchangeAsync(application, code, pkce.Verifier);

        // The other application names its own person; the one at this browser is somebody else.
        var leaving = await browser.GetAsync(new Uri($"/connect/logout?id_token_hint={Uri.EscapeDataString(othersIdToken)}", UriKind.Relative));
        var location = leaving.Headers.Location!.OriginalString;
        var flow = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;
        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync(new Uri($"/api/v1/logout-flows/{flow}", UriKind.Relative), null)).StatusCode);

        // Nothing of the person at this browser ended: still signed in, and what they were given still works.
        var again = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge), UriKind.Relative));
        Assert.StartsWith(Callback, again.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(application, tokens.Body.GetProperty("refresh_token").GetString()!)).Status);
    }

    /// <summary>Signs the person in at the browser, through a flow of the application, and stops where the authorization request comes back.</summary>
    private static async Task<HttpResponseMessage> SignInAsync(HttpClient browser, string clientId, string address)
    {
        var flow = await StartAsync(browser, clientId, Pkce.New().Challenge);
        var signedIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        using var next = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        return await browser.GetAsync(new Uri(next.RootElement.GetProperty("redirect_to").GetString()!, UriKind.Relative));
    }

    /// <summary>Signs in, and returns the id of the consent flow the application's request opens.</summary>
    private static async Task<string> ConsentFlowAsync(HttpClient browser, string clientId, string address, Pkce pkce)
    {
        var flow = await StartAsync(browser, clientId, pkce.Challenge);
        var signedIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });
        using var next = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        var back = await browser.GetAsync(new Uri(next.RootElement.GetProperty("redirect_to").GetString()!, UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        var location = back.Headers.Location!.OriginalString;
        Assert.StartsWith("/consent?flow=", location);
        return HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;
    }

    /// <summary>Allows the scopes, follows the browser back to the authorization endpoint and returns the code it gets.</summary>
    private static async Task<string> AcceptAsync(HttpClient browser, string flow, string[] scopes, bool remember)
    {
        var accepted = await browser.PostAsJsonAsync(new Uri($"/api/v1/consent-flows/{flow}/accept", UriKind.Relative), new { grant_scope = scopes, remember });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using var next = JsonDocument.Parse(await accepted.Content.ReadAsStringAsync());
        Assert.Equal("redirect", next.RootElement.GetProperty("next").GetString());
        var back = await browser.GetAsync(new Uri(next.RootElement.GetProperty("redirect_to").GetString()!, UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.StartsWith(Callback, back.Headers.Location!.OriginalString);
        return HttpUtility.ParseQueryString(back.Headers.Location.Query)["code"]!;
    }
}
