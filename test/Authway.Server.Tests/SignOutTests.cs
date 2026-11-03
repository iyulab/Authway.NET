using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Server.Tests;

/// <summary>What an application may ask about the person once they are signed in, and how they sign out.</summary>
public abstract partial class ServerTests
{
    private const string SignedOut = "https://app.example.test/signed-out";

    [Fact]
    public async Task UserInfo_SaysWhatTheScopesAllow_AboutTheAccountAsItIsNow()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var tokens = await ExchangeAsync(application, code, pkce.Verifier);
        var accessToken = tokens.Body.GetProperty("access_token").GetString()!;

        // Changed after the token was issued: the answer is what is true now.
        using (var scope = server.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var person = await users.FindByEmailAsync(address);
            person!.DisplayName = "Renamed Person";
            await users.UpdateAsync(person);
        }

        var response = await UserInfoAsync(accessToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Claims(accessToken).GetProperty("sub").GetString(), body.RootElement.GetProperty("sub").GetString());
        Assert.Equal(address, body.RootElement.GetProperty("email").GetString());
        Assert.False(body.RootElement.GetProperty("email_verified").GetBoolean());
        Assert.Equal("Renamed Person", body.RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public async Task UserInfo_AnswersOnlyWhatTheTokenWasGranted()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, pkce.Challenge, scope: "openid");
        var signedIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });
        using var next = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        var back = await browser.GetAsync(new Uri(next.RootElement.GetProperty("redirect_to").GetString()!, UriKind.Relative));
        var tokens = await ExchangeAsync(application, HttpUtility.ParseQueryString(back.Headers.Location!.Query)["code"]!, pkce.Verifier);

        var response = await UserInfoAsync(tokens.Body.GetProperty("access_token").GetString()!);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("sub", body.RootElement.EnumerateObject().Select(p => p.Name).Single());
    }

    [Fact]
    public async Task UserInfo_RefusesWhoHoldsNoToken_AndAnAccountThatIsLockedOut()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var accessToken = (await ExchangeAsync(application, code, pkce.Verifier)).Body.GetProperty("access_token").GetString()!;

        Assert.Equal(HttpStatusCode.Unauthorized, (await server.Client.GetAsync(new Uri("/connect/userinfo", UriKind.Relative))).StatusCode);

        using (var scope = server.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await users.SetLockoutEndDateAsync((await users.FindByEmailAsync(address))!, DateTimeOffset.UtcNow.AddHours(1));
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(accessToken)).StatusCode);
    }

    [Fact]
    public async Task SigningOut_EndsTheSession_StopsWhatThePersonWasGiven_AndSendsTheBrowserBackToTheApplication()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(browser, application, address, pkce);
        var tokens = await ExchangeAsync(application, code, pkce.Verifier);

        var leaving = await browser.GetAsync(new Uri($"/connect/logout?id_token_hint={Uri.EscapeDataString(tokens.Body.GetProperty("id_token").GetString()!)}&post_logout_redirect_uri={Uri.EscapeDataString(SignedOut)}&state=bye", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, leaving.StatusCode);
        var location = leaving.Headers.Location!.OriginalString;
        Assert.StartsWith("/logout?flow=", location);
        var flow = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;

        // A sign-in flow is not a sign-out flow, whatever its id is.
        var signInFlow = await StartAsync(server.CreateClient(followRedirects: false), application, Pkce.New().Challenge);
        var wrongKind = await browser.PostAsync(new Uri($"/api/v1/logout-flows/{signInFlow}", UriKind.Relative), null);
        Assert.True(wrongKind.StatusCode == HttpStatusCode.BadRequest, $"{wrongKind.StatusCode}: {await wrongKind.Content.ReadAsStringAsync()}");
        var unknown = await browser.PostAsync(new Uri("/api/v1/logout-flows/not-a-flow", UriKind.Relative), null);
        Assert.True(unknown.StatusCode == HttpStatusCode.BadRequest, $"{unknown.StatusCode}: {await unknown.Content.ReadAsStringAsync()}");

        var done = await browser.PostAsync(new Uri($"/api/v1/logout-flows/{flow}", UriKind.Relative), null);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        using var next = JsonDocument.Parse(await done.Content.ReadAsStringAsync());
        Assert.Equal("redirect", next.RootElement.GetProperty("next").GetString());
        Assert.Equal($"{SignedOut}?state=bye", next.RootElement.GetProperty("redirect_to").GetString());

        // The session is gone: the next request for a code asks the person to sign in.
        var again = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge), UriKind.Relative));
        Assert.StartsWith("/login?flow=", again.Headers.Location!.OriginalString);

        // What they were given is gone with it.
        var refreshed = await RefreshAsync(application, tokens.Body.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.Status);
        Assert.Equal("invalid_grant", refreshed.Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(tokens.Body.GetProperty("access_token").GetString()!)).StatusCode);

        // And the flow is spent.
        var twice = await browser.PostAsync(new Uri($"/api/v1/logout-flows/{flow}", UriKind.Relative), null);
        Assert.Equal(HttpStatusCode.Gone, twice.StatusCode);
    }

    [Fact]
    public async Task SigningOut_WithoutSayingWhereTo_GoesHome()
    {
        var browser = server.CreateClient(followRedirects: false);

        var leaving = await browser.GetAsync(new Uri("/connect/logout", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, leaving.StatusCode);
        var location = leaving.Headers.Location!.OriginalString;
        var flow = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;

        var done = await browser.PostAsync(new Uri($"/api/v1/logout-flows/{flow}", UriKind.Relative), null);
        using var next = JsonDocument.Parse(await done.Content.ReadAsStringAsync());
        Assert.Equal("/", next.RootElement.GetProperty("redirect_to").GetString());
    }

    private async Task<HttpResponseMessage> UserInfoAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/connect/userinfo", UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await server.Client.SendAsync(request);
    }
}
