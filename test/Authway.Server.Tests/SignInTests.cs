using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server.Tests;

/// <summary>
/// The sign-in an application starts: it sends the browser to the authorization
/// endpoint, the person answers on the screen the login flow API serves, and the
/// application trades the code it gets back for tokens.
/// </summary>
public abstract partial class ServerTests
{
    private const string Password = "correct-Horse-9";
    private const string Callback = "https://app.example.test/callback";

    [Fact]
    public async Task Authorizing_WithoutASession_OpensAFlow_TheScreenCanAskAbout()
    {
        var application = await RegisterApplicationAsync();
        var browser = server.CreateClient(followRedirects: false);

        var start = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge, loginHint: "person@example.test", locales: "ko en"), UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var location = start.Headers.Location!.OriginalString;
        Assert.StartsWith("/login?flow=", location);
        var flow = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;
        Assert.True(flow.Length >= 24, "the flow id is not guessable");

        var screen = await browser.GetAsync(new Uri($"/api/v1/login-flows/{Uri.EscapeDataString(flow)}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, screen.StatusCode);
        using var body = JsonDocument.Parse(await screen.Content.ReadAsStringAsync());
        var form = body.RootElement;
        Assert.Equal("form", form.GetProperty("next").GetString());
        Assert.Equal(flow, form.GetProperty("flow").GetString());
        Assert.Equal("Application under test", form.GetProperty("client_name").GetString());
        Assert.Equal(application, form.GetProperty("client").GetProperty("client_id").GetString());
        Assert.Equal("email", form.GetProperty("client").GetProperty("sign_in_methods").EnumerateArray().Select(m => m.GetString()).Single());
        Assert.Contains("openid", form.GetProperty("requested_scope").EnumerateArray().Select(s => s.GetString()));
        var hints = form.GetProperty("hints");
        Assert.Equal("person@example.test", hints.GetProperty("login_hint").GetString());
        Assert.Equal("ko,en", string.Join(',', hints.GetProperty("ui_locales").EnumerateArray().Select(l => l.GetString())));
    }

    [Fact]
    public async Task AFlowThatDoesNotExist_IsRefused_ThePlainWay()
    {
        var response = await server.Client.GetAsync(new Uri("/api/v1/login-flows/not-a-flow", UriKind.Relative));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("about:blank", body.RootElement.GetProperty("type").GetString());
        Assert.Equal("Bad Request", body.RootElement.GetProperty("title").GetString());
        Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("invalid_flow", body.RootElement.GetProperty("code").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("detail").GetString()));
    }

    [Fact]
    public async Task APasswordThatIsNotRight_IsRefused_WhoeverTheAddressBelongsTo()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);

        var wrongPassword = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = "not-the-password" });
        var unknownAddress = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = $"nobody-{Guid.NewGuid():N}@example.test", password = Password });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownAddress.StatusCode);
        var first = await wrongPassword.Content.ReadAsStringAsync();
        Assert.Equal(first, await unknownAddress.Content.ReadAsStringAsync());
        using var body = JsonDocument.Parse(first);
        Assert.Equal("invalid_credentials", body.RootElement.GetProperty("code").GetString());

        // The flow is still open: the person may try again.
        var screen = await browser.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, screen.StatusCode);
    }

    [Fact]
    public async Task SigningIn_ReturnsTheBrowserToTheApplication_WithACodeThatBuysTokens()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var flow = await StartAsync(browser, application, pkce.Challenge);

        var signedIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password, remember = false });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        using var next = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        Assert.Equal("redirect", next.RootElement.GetProperty("next").GetString());
        var resume = next.RootElement.GetProperty("redirect_to").GetString()!;
        Assert.StartsWith("/connect/authorize?", resume);

        // The browser goes back to the authorization endpoint, now with a session, and is sent on to the application.
        var back = await browser.GetAsync(new Uri(resume, UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        var returned = back.Headers.Location!;
        Assert.StartsWith(Callback, returned.OriginalString);
        var query = HttpUtility.ParseQueryString(returned.Query);
        Assert.Equal("state-123", query["state"]);
        var code = query["code"]!;

        // The flow ended with the sign-in: its id says so, and cannot sign anyone in again.
        var ended = await browser.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Gone, ended.StatusCode);
        using var endedBody = JsonDocument.Parse(await ended.Content.ReadAsStringAsync());
        Assert.Equal("flow_expired", endedBody.RootElement.GetProperty("code").GetString());

        var tokens = await ExchangeAsync(application, code, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        var access = Claims(tokens.Body.GetProperty("access_token").GetString()!);
        Assert.Equal(address, access.GetProperty("email").GetString());
        Assert.True(Guid.TryParse(access.GetProperty("sub").GetString(), out _), "the subject is the account's id");
        var identity = Claims(tokens.Body.GetProperty("id_token").GetString()!);
        Assert.Equal(access.GetProperty("sub").GetString(), identity.GetProperty("sub").GetString());
        Assert.Equal(address, identity.GetProperty("email").GetString());
        Assert.False(identity.GetProperty("email_verified").GetBoolean());
        Assert.Equal("Person Under Test", identity.GetProperty("name").GetString());
        var audience = identity.GetProperty("aud");
        Assert.Equal(application, audience.ValueKind == JsonValueKind.Array ? audience.EnumerateArray().Select(a => a.GetString()).Single() : audience.GetString());

        // The code is good once.
        var again = await ExchangeAsync(application, code, pkce.Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, again.Status);
        Assert.Equal("invalid_grant", again.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ACodeIsNotWorthAnything_ToWhoeverDoesNotHoldTheVerifier()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var code = await SignInAndGetCodeAsync(browser, application, address, Pkce.New());

        var stolen = await ExchangeAsync(application, code, Pkce.New().Verifier);

        Assert.Equal(HttpStatusCode.BadRequest, stolen.Status);
        Assert.Equal("invalid_grant", stolen.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ARefreshToken_BuysNewTokens_UntilTheAccountIsLockedOut()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(browser, application, address, pkce);
        var first = await ExchangeAsync(application, code, pkce.Verifier);
        var refreshToken = first.Body.GetProperty("refresh_token").GetString()!;

        var renewed = await RefreshAsync(application, refreshToken);
        Assert.Equal(HttpStatusCode.OK, renewed.Status);
        Assert.Equal(address, Claims(renewed.Body.GetProperty("access_token").GetString()!).GetProperty("email").GetString());

        using (var scope = server.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var person = await users.FindByEmailAsync(address);
            await users.SetLockoutEndDateAsync(person!, DateTimeOffset.UtcNow.AddHours(1));
        }

        var locked = await RefreshAsync(application, renewed.Body.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, locked.Status);
        Assert.Equal("invalid_grant", locked.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorizing_WithoutASession_WhenTheApplicationAsksNotToBeAsked_IsAnErrorBackToIt()
    {
        var application = await RegisterApplicationAsync();
        var browser = server.CreateClient(followRedirects: false);

        var response = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge, prompt: "none"), UriKind.Relative));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(Callback, response.Headers.Location!.OriginalString);
        var query = HttpUtility.ParseQueryString(response.Headers.Location.Query);
        Assert.Equal("login_required", query["error"]);
        Assert.Equal("state-123", query["state"]);
    }

    [Fact]
    public async Task AskingToSignInAgain_OpensAFlowEvenWithASession_AndDoesNotAskAgainWhenItComesBack()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        await SignInAndGetCodeAsync(browser, application, address, Pkce.New());

        var again = await browser.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge, prompt: "login"), UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, again.StatusCode);
        Assert.StartsWith("/login?flow=", again.Headers.Location!.OriginalString);

        // The flow is not satisfied by the session that was there: the person is asked.
        var flow = HttpUtility.ParseQueryString(again.Headers.Location.OriginalString[(again.Headers.Location.OriginalString.IndexOf('?') + 1)..])["flow"]!;
        var form = await browser.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative));
        using var body = JsonDocument.Parse(await form.Content.ReadAsStringAsync());
        Assert.Equal("redirect", body.RootElement.GetProperty("next").GetString());
        var resume = body.RootElement.GetProperty("redirect_to").GetString()!;
        Assert.DoesNotContain("prompt=login", resume);
    }

    private async Task<string> RegisterApplicationAsync()
    {
        using var scope = server.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = $"app-{Guid.NewGuid():N}";
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "Application under test",
            RedirectUris = { new Uri(Callback) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        };
        await applications.CreateAsync(descriptor);
        return clientId;
    }

    private async Task<(string Application, string Address)> RegisterApplicationAndPersonAsync()
    {
        var application = await RegisterApplicationAsync();
        using var scope = server.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var address = $"person-{Guid.NewGuid():N}@example.test";
        var created = await users.CreateAsync(new ApplicationUser { UserName = address, Email = address, DisplayName = "Person Under Test" }, Password);
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));
        return (application, address);
    }

    private static string AuthorizeUrl(string clientId, string challenge, string? prompt = null, string? loginHint = null, string? locales = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid email profile offline_access",
            ["state"] = "state-123",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["prompt"] = prompt,
            ["login_hint"] = loginHint,
            ["ui_locales"] = locales,
        };
        return "/connect/authorize?" + string.Join('&', query.Where(p => p.Value is not null).Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value!)}"));
    }

    /// <summary>The application sends the browser to the authorization endpoint; the flow id it is sent on to comes back.</summary>
    private static async Task<string> StartAsync(HttpClient browser, string clientId, string challenge)
    {
        var start = await browser.GetAsync(new Uri(AuthorizeUrl(clientId, challenge), UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var location = start.Headers.Location!.OriginalString;
        return HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..])["flow"]!;
    }

    private static async Task<string> SignInAndGetCodeAsync(HttpClient browser, string clientId, string address, Pkce pkce)
    {
        var flow = await StartAsync(browser, clientId, pkce.Challenge);
        var signedIn = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        using var next = JsonDocument.Parse(await signedIn.Content.ReadAsStringAsync());
        var back = await browser.GetAsync(new Uri(next.RootElement.GetProperty("redirect_to").GetString()!, UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        return HttpUtility.ParseQueryString(back.Headers.Location!.Query)["code"]!;
    }

    private Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(string clientId, string code, string verifier) =>
        TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["redirect_uri"] = Callback,
            ["code_verifier"] = verifier,
        });

    private Task<(HttpStatusCode Status, JsonElement Body)> RefreshAsync(string clientId, string refreshToken) =>
        TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken,
        });

    private async Task<(HttpStatusCode Status, JsonElement Body)> TokenAsync(Dictionary<string, string> form)
    {
        var response = await server.Client.PostAsync(new Uri("/connect/token", UriKind.Relative), new FormUrlEncodedContent(form));
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (response.StatusCode, document.RootElement.Clone());
    }

    private static JsonElement Claims(string jwt)
    {
        using var document = JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.Split('.')[1]));
        return document.RootElement.Clone();
    }

    private sealed record Pkce(string Verifier, string Challenge)
    {
        public static Pkce New()
        {
            var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            return new Pkce(verifier, Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
        }
    }
}
