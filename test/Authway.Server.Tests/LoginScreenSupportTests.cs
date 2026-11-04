using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;

namespace Authway.Server.Tests;

/// <summary>What the sign-in screens and a deployment ask of the server besides the sign-in itself.</summary>
public abstract partial class ServerTests
{
    private static readonly string[] RedirectToCallback = [Callback];

    [Fact]
    public async Task Health_NamesTheVersion_AndTheMigrationsThisBuildShips()
    {
        var health = await BodyOfAsync(await server.Client.GetAsync(new Uri("/health", UriKind.Relative)));
        Assert.Equal("ok", health.GetProperty("status").GetString());
        Assert.False(string.IsNullOrEmpty(health.GetProperty("version").GetString()));

        var migrations = health.GetProperty("migrations").EnumerateArray().Select(m => m.GetString()!).ToList();
        Assert.NotEmpty(migrations);
        Assert.Equal(migrations.Order(StringComparer.Ordinal), migrations);
        Assert.Contains(migrations, m => m.EndsWith("_AddEmailTokens", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SigningInWithAnotherProvider_EndsTheFlow_AndTellsTheApplicationItCannotBeMet()
    {
        var (application, _) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var social = new Uri($"/api/v1/login-flows/{flow}/social/google", UriKind.Relative);

        var navigated = await browser.GetAsync(social);
        Assert.Equal(HttpStatusCode.Redirect, navigated.StatusCode);
        var location = navigated.Headers.Location!.OriginalString;
        Assert.StartsWith(Callback, location, StringComparison.Ordinal);
        var query = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..]);
        Assert.Equal("invalid_request", query["error"]);
        Assert.Equal("state-123", query["state"]);

        // The flow was used up.
        Assert.Equal(HttpStatusCode.Gone, (await browser.GetAsync(social)).StatusCode);
        await AssertRefusedAsync(await browser.GetAsync(new Uri("/api/v1/login-flows/unknown/social/google", UriKind.Relative)), HttpStatusCode.BadRequest, "invalid_flow");
    }

    [Fact]
    public async Task AnApplicationsLogo_IsNamedInTheFlow_UntilItIsCleared()
    {
        var admin = AdminClient(AdminKey);
        var created = (await RegisterClientAsync(admin, new
        {
            tenant_id = TenantId,
            name = $"logo-{Guid.NewGuid():N}"[..20],
            @public = true,
            redirect_uris = RedirectToCallback,
            allowed_origins = AppOrigin,
            grant_types = AuthorizationCode,
            scopes = Openid,
        })).GetProperty("client");
        var application = created.GetProperty("client_id").GetString()!;
        var id = created.GetProperty("id").GetString()!;
        var browser = server.CreateClient(followRedirects: false);
        const string scope = "openid";

        var logo = "https://app.example.test/logo.png";
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(new Uri($"/api/v1/clients/{id}", UriKind.Relative), new { logo })).StatusCode);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge, scope);
        var form = await BodyOfAsync(await browser.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative)));
        Assert.Equal(logo, form.GetProperty("client_logo_uri").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync(new Uri($"/api/v1/clients/{id}", UriKind.Relative), new { logo = "http://app.example.test/logo.png" })).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(new Uri($"/api/v1/clients/{id}", UriKind.Relative), new { logo = string.Empty })).StatusCode);
        var cleared = await BodyOfAsync(await browser.GetAsync(new Uri($"/api/v1/login-flows/{await StartAsync(browser, application, Pkce.New().Challenge, scope)}", UriKind.Relative)));
        Assert.False(cleared.TryGetProperty("client_logo_uri", out _));
    }

    [Fact]
    public async Task TheSignInFlow_AndAPasswordReset_SayThatPeopleAreOnlyInvited_TheSameForEveryAddress()
    {
        var (application, known) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);

        // The screen is told how people come to have an account here, to say so to someone who cannot sign in.
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var form = await BodyOfAsync(await browser.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative)));
        Assert.Equal("invite_only", form.GetProperty("signup_mode").GetString());

        // A reset that names the application says it too — alike for an address with an account and one without.
        var client = server.CreateClient(followRedirects: true);
        var forKnown = await client.PostAsJsonAsync(ForgotPassword, new { email = known, client_id = application });
        var forNobody = await client.PostAsJsonAsync(ForgotPassword, new { email = $"nobody-{Guid.NewGuid():N}@example.test", client_id = application });
        Assert.Equal(HttpStatusCode.OK, forNobody.StatusCode);
        var answer = await forKnown.Content.ReadAsStringAsync();
        Assert.Equal(answer, await forNobody.Content.ReadAsStringAsync());
        Assert.Equal("invite_only", (await BodyOfAsync(forKnown)).GetProperty("signup_mode").GetString());

        // A request for a new verification link says the same; with no application named there is no tenant to speak of.
        var verification = await BodyOfAsync(await client.PostAsJsonAsync(SendVerification, new { email = known, client_id = application }));
        Assert.Equal("invite_only", verification.GetProperty("signup_mode").GetString());
        var anonymous = await BodyOfAsync(await client.PostAsJsonAsync(ForgotPassword, new { email = known }));
        Assert.False(anonymous.TryGetProperty("signup_mode", out _));
    }

    [Fact]
    public async Task Reconciling_TheClientsWithTheAuthorizationServer_FindsThemInStep()
    {
        var admin = AdminClient(AdminKey);
        await RegisterApplicationAndPersonAsync();

        var synced = await BodyOfAsync(await admin.PostAsync(new Uri("/api/v1/clients/sync-hydra", UriKind.Relative), null));
        Assert.True(synced.GetProperty("synced").GetInt32() >= 1);
        Assert.Equal(0, synced.GetProperty("failed").GetInt32());
        using var anonymous = server.CreateClientWith(new Dictionary<string, string?> { ["Authway:Admin:ApiKey"] = AdminKey });
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync(new Uri("/api/v1/clients/sync-hydra", UriKind.Relative), null)).StatusCode);
    }
}
