using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authway.Server.Tests;

/// <summary>An administrator registers, reads, changes and removes the applications that sign people in.</summary>
public abstract partial class ServerTests
{
    private static readonly string[] NoStrings = [];
    private static readonly string[] AuthorizationCode = ["authorization_code"];
    private static readonly string[] AuthorizationCodeRefreshToken = ["authorization_code", "refresh_token"];
    private static readonly string[] ClientCredentials = ["client_credentials"];
    private static readonly string[] HttpLocalhost3000 = ["http://localhost:3000"];
    private static readonly string[] HttpLocalhost3000Callback = ["http://localhost:3000/callback"];
    private static readonly string[] HttpsAppExampleTestCb = ["https://app.example.test/cb"];
    private static readonly string[] ImplicitPasswordNotAGrant = ["implicit", "password", "not-a-grant"];
    private static readonly string[] NotAUrl = ["not a url"];
    private static readonly string[] Openid = ["openid"];
    private static readonly string[] OpenidProfileEmail = ["openid", "profile", "email"];
    private const string TenantId = "00000000-0000-0000-0000-000000000001";

    private static readonly Uri Clients = new("/api/v1/clients", UriKind.Relative);

    private static Uri ClientAt(string id, string rest = "") => new($"/api/v1/clients/{id}{rest}", UriKind.Relative);

    private static object PublicClientBody(string? name = null) => new
    {
        tenant_id = TenantId,
        name = name ?? $"admin-test-{Guid.NewGuid():N}"[..20],
        @public = true,
        redirect_uris = HttpLocalhost3000Callback,
        post_logout_redirect_uris = HttpLocalhost3000,
        allowed_origins = HttpLocalhost3000,
        grant_types = AuthorizationCodeRefreshToken,
        scopes = OpenidProfileEmail,
    };

    private static async Task<JsonElement> BodyOfAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    private static async Task<JsonElement> RegisterClientAsync(HttpClient admin, object body)
    {
        var response = await admin.PostAsJsonAsync(Clients, body);
        Assert.True(response.StatusCode == HttpStatusCode.Created, await response.Content.ReadAsStringAsync());
        return await BodyOfAsync(response);
    }

    private static async Task AssertRefusedAsync(HttpResponseMessage response, HttpStatusCode status, string code, string? field = null)
    {
        Assert.Equal(status, response.StatusCode);
        var body = await BodyOfAsync(response);
        Assert.Equal(code, body.GetProperty("code").GetString());
        if (field is not null)
        {
            Assert.Equal(field, body.GetProperty("field").GetString());
        }
    }

    [Fact]
    public async Task APublicClient_IsRegistered_AndReadBackAsItWasGiven()
    {
        var admin = AdminClient(AdminKey);
        var created = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client");

        Assert.True(created.GetProperty("public").GetBoolean());
        Assert.Equal("none", created.GetProperty("token_endpoint_auth_method").GetString());
        Assert.Equal(TenantId, created.GetProperty("tenant_id").GetString());
        Assert.Equal(["http://localhost:3000/callback"], created.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["http://localhost:3000"], created.GetProperty("allowed_origins").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["email"], created.GetProperty("enabled_auth_providers").EnumerateArray().Select(e => e.GetString()));

        var read = await admin.GetAsync(ClientAt(created.GetProperty("id").GetString()!));
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal(created.GetProperty("client_id").GetString(), (await BodyOfAsync(read)).GetProperty("client").GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task AnUpdate_ChangesOnlyWhatItSends()
    {
        var admin = AdminClient(AdminKey);
        var created = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client");
        var id = created.GetProperty("id").GetString()!;

        var update = await admin.PutAsJsonAsync(ClientAt(id), new { name = "renamed", skip_consent = true, skip_logout_consent = true });
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        Assert.Equal("ok", (await BodyOfAsync(update)).GetProperty("sync_status").GetProperty("state").GetString());

        var after = (await BodyOfAsync(await admin.GetAsync(ClientAt(id)))).GetProperty("client");
        Assert.Equal("renamed", after.GetProperty("name").GetString());
        Assert.True(after.GetProperty("skip_consent").GetBoolean());
        Assert.True(after.GetProperty("skip_logout_consent").GetBoolean());
        Assert.Equal(created.GetProperty("redirect_uris").ToString(), after.GetProperty("redirect_uris").ToString());
        Assert.Equal(created.GetProperty("allowed_origins").ToString(), after.GetProperty("allowed_origins").ToString());
    }

    [Fact]
    public async Task AnUpdateThatCannotBeApplied_IsRefusedWithACode()
    {
        var admin = AdminClient(AdminKey);
        var id = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client").GetProperty("id").GetString()!;

        await AssertRefusedAsync(await admin.PutAsJsonAsync(ClientAt(id), new { redirect_uris = NotAUrl }), HttpStatusCode.BadRequest, "invalid_redirect_uri", "redirect_uris");
        await AssertRefusedAsync(await admin.PutAsJsonAsync(ClientAt(id), new { enabled_auth_providers = NoStrings }), HttpStatusCode.BadRequest, "invalid_enabled_auth_providers", "enabled_auth_providers");
        foreach (var grant in ImplicitPasswordNotAGrant)
        {
            await AssertRefusedAsync(await admin.PutAsJsonAsync(ClientAt(id), new { grant_types = new[] { "authorization_code", grant } }), HttpStatusCode.BadRequest, "unsupported_grant_type", "grant_types");
        }

        var unchanged = (await BodyOfAsync(await admin.GetAsync(ClientAt(id)))).GetProperty("client");
        Assert.DoesNotContain("implicit", unchanged.GetProperty("grant_types").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task AClientThatIsNotCoherent_IsRefused()
    {
        var admin = AdminClient(AdminKey);
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "no-origins", @public = true, redirect_uris = HttpsAppExampleTestCb, grant_types = AuthorizationCode, scopes = Openid }),
            HttpStatusCode.BadRequest, "public_client_missing_allowed_origins", "allowed_origins");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "public-secret-grant", @public = true, grant_types = ClientCredentials, scopes = Openid }),
            HttpStatusCode.BadRequest, "public_client_with_client_credentials", "grant_types");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "half-credentials", client_id = "half-credentials", grant_types = ClientCredentials, scopes = Openid }),
            HttpStatusCode.BadRequest, "confidential_client_partial_credentials");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "no-redirect", grant_types = AuthorizationCode, scopes = Openid }),
            HttpStatusCode.BadRequest, "redirect_grant_without_redirect_uris", "redirect_uris");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "keys", token_endpoint_auth_method = "private_key_jwt", grant_types = ClientCredentials, scopes = Openid }),
            HttpStatusCode.BadRequest, "invalid_token_endpoint_auth_method", "token_endpoint_auth_method");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "google", google_oauth_enabled = true, grant_types = ClientCredentials, scopes = Openid }),
            HttpStatusCode.BadRequest, "provider_unavailable", "google_oauth_enabled");
        await AssertRefusedAsync(
            await admin.PostAsJsonAsync(Clients, new { name = "github", github_client_id = "app", grant_types = ClientCredentials, scopes = Openid }),
            HttpStatusCode.BadRequest, "provider_unavailable", "github_client_id");
    }

    [Theory]
    [InlineData("initiate_login_uri", "http://app.example.test/x")]
    [InlineData("client_uri", "https://app.example.test/x#fragment")]
    [InlineData("logo", "not an address")]
    public async Task AnApplicationAddress_ThatIsNotHttps_OrHasAFragment_IsRefusedNamingTheMember(string member, string address)
    {
        var admin = AdminClient(AdminKey);
        var id = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client").GetProperty("id").GetString()!;

        var response = await admin.PutAsJsonAsync(ClientAt(id), new Dictionary<string, string> { [member] = address });

        await AssertRefusedAsync(response, HttpStatusCode.BadRequest, $"invalid_{member}", member);
    }

    [Fact]
    public async Task AListIsAtMost100_NewestFirst_AndNamesATenantOrNone()
    {
        var admin = AdminClient(AdminKey);
        var first = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client").GetProperty("id").GetString();
        await Task.Delay(20);
        var second = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client").GetProperty("id").GetString();

        var page = await BodyOfAsync(await admin.GetAsync(new Uri($"/api/v1/clients?tenant_id={TenantId}&limit=500", UriKind.Relative)));
        Assert.Equal(100, page.GetProperty("limit").GetInt32());
        var ids = page.GetProperty("clients").EnumerateArray().Select(c => c.GetProperty("id").GetString()).ToList();
        Assert.True(ids.IndexOf(second) < ids.IndexOf(first), "the newer client comes first");
        Assert.True(page.GetProperty("total").GetInt32() >= 2);

        var other = await admin.GetAsync(new Uri("/api/v1/clients?tenant_id=00000000-0000-4000-8000-000000000000", UriKind.Relative));
        await AssertRefusedAsync(other, HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task AClientThatDoesNotExist_IsNotFound()
    {
        var admin = AdminClient(AdminKey);
        await AssertRefusedAsync(await admin.GetAsync(ClientAt(Guid.NewGuid().ToString())), HttpStatusCode.NotFound, "not_found");
        await AssertRefusedAsync(await admin.GetAsync(ClientAt("not-an-id")), HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TheTenantInTheBody_AndTheHeader_MustBeTheSame()
    {
        var admin = AdminClient(AdminKey);
        admin.DefaultRequestHeaders.Add("X-Tenant-ID", TenantId);
        var body = new { name = "tenant-test", tenant_id = "00000000-0000-4000-8000-000000000000", grant_types = ClientCredentials, scopes = Openid };
        await AssertRefusedAsync(await admin.PostAsJsonAsync(Clients, body), HttpStatusCode.BadRequest, "invalid_request", "tenant_id");

        var fromHeader = await RegisterClientAsync(admin, new { name = "tenant-from-header", grant_types = ClientCredentials, scopes = Openid });
        Assert.Equal(TenantId, fromHeader.GetProperty("client").GetProperty("tenant_id").GetString());
    }

    [Fact]
    public async Task AConfidentialClient_GetsItsSecretOnce_AndCanBeGivenAnother()
    {
        var admin = AdminClient(AdminKey);
        var created = await RegisterClientAsync(admin, new { name = "machine", grant_types = ClientCredentials, scopes = Openid });
        var client = created.GetProperty("client");
        var credentials = created.GetProperty("credentials");
        var clientId = credentials.GetProperty("client_id").GetString()!;
        var secret = credentials.GetProperty("client_secret").GetString()!;
        Assert.Equal(clientId, client.GetProperty("client_id").GetString());
        Assert.False(client.TryGetProperty("client_secret", out _), "a read never carries the secret");

        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(clientId, secret)).StatusCode);

        var regenerated = await admin.PostAsync(ClientAt(client.GetProperty("id").GetString()!, "/regenerate-secret"), null);
        Assert.Equal(HttpStatusCode.OK, regenerated.StatusCode);
        var fresh = (await BodyOfAsync(regenerated)).GetProperty("credentials").GetProperty("client_secret").GetString()!;
        Assert.NotEqual(secret, fresh);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(clientId, secret)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(clientId, fresh)).StatusCode);
    }

    [Fact]
    public async Task APublicClient_HasNoSecretToRegenerate()
    {
        var admin = AdminClient(AdminKey);
        var id = (await RegisterClientAsync(admin, PublicClientBody())).GetProperty("client").GetProperty("id").GetString()!;

        await AssertRefusedAsync(await admin.PostAsync(ClientAt(id, "/regenerate-secret"), null), HttpStatusCode.BadRequest, "public_client_has_no_secret");
    }

    [Fact]
    public async Task AChosenClientId_IsRefusedWhileRegistered_AndFreeOnceDeleted()
    {
        var admin = AdminClient(AdminKey);
        var clientId = $"chosen-{Guid.NewGuid():N}"[..24];
        object Chosen(string secret) => new { name = clientId, client_id = clientId, client_secret = secret, grant_types = ClientCredentials, scopes = Openid };

        var id = (await RegisterClientAsync(admin, Chosen("first-secret-0123456789"))).GetProperty("client").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(clientId, "first-secret-0123456789")).StatusCode);

        await AssertRefusedAsync(await admin.PostAsJsonAsync(Clients, Chosen("second-secret-0123456789")), HttpStatusCode.Conflict, "client_id_taken", "client_id");
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(clientId, "first-secret-0123456789")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync(ClientAt(id))).StatusCode);
        await RegisterClientAsync(admin, Chosen("again-secret-0123456789"));
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(clientId, "again-secret-0123456789")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(clientId, "first-secret-0123456789")).StatusCode);
    }

    [Fact]
    public async Task AClientId_InTheFormOfAUserId_IsRefused()
    {
        var admin = AdminClient(AdminKey);
        var response = await admin.PostAsJsonAsync(Clients, new { name = "uuid-form", client_id = Guid.NewGuid().ToString(), client_secret = "a-secret-0123456789", grant_types = ClientCredentials, scopes = Openid });

        await AssertRefusedAsync(response, HttpStatusCode.BadRequest, "invalid_client_id", "client_id");
    }

    [Fact]
    public async Task ARegisteredPublicClient_CanSignAPersonIn()
    {
        var admin = AdminClient(AdminKey);
        var created = (await RegisterClientAsync(admin, new
        {
            name = "sign-in",
            @public = true,
            skip_consent = true,
            redirect_uris = new[] { Callback },
            allowed_origins = new[] { new Uri(Callback).GetLeftPart(UriPartial.Authority) },
            grant_types = AuthorizationCodeRefreshToken,
            scopes = OpenidProfileEmail,
        })).GetProperty("client");

        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, created.GetProperty("client_id").GetString()!, Pkce.New().Challenge, "openid email profile");

        Assert.False(string.IsNullOrEmpty(flow));
    }

    private async Task<HttpResponseMessage> TokenAsync(string clientId, string secret) =>
        await server.Client.PostAsync(new Uri("/connect/token", UriKind.Relative), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }));
}
