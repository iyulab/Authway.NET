using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Server.Tests;

/// <summary>An administrator looks people up, renames and removes them; a person ends every session they have.</summary>
public abstract partial class ServerTests
{
    private static readonly Uri Users = new("/api/v1/users", UriKind.Relative);

    private static Uri UserAt(string id) => new($"/api/v1/users/{id}", UriKind.Relative);

    private async Task<(string Id, string Email)> NewPersonAsync()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        using var scope = server.Services.CreateScope();
        var person = await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(address);
        return (person!.Id.ToString(), address);
    }

    [Fact]
    public async Task APerson_IsFound_ByListAndSearchAndId()
    {
        var admin = AdminClient(AdminKey);
        var (id, email) = await NewPersonAsync();

        var page = await BodyOfAsync(await admin.GetAsync(new Uri("/api/v1/users?limit=100", UriKind.Relative)));
        Assert.Equal(100, page.GetProperty("limit").GetInt32());
        Assert.Contains(id, page.GetProperty("users").EnumerateArray().Select(u => u.GetProperty("id").GetString()));

        var found = (await BodyOfAsync(await admin.PostAsJsonAsync(new Uri("/api/v1/users/search", UriKind.Relative), new { email = email.ToUpperInvariant() }))).GetProperty("users");
        Assert.Equal(id, Assert.Single(found.EnumerateArray()).GetProperty("id").GetString());
        var none = (await BodyOfAsync(await admin.PostAsJsonAsync(new Uri("/api/v1/users/search", UriKind.Relative), new { email = "nobody@example.test" }))).GetProperty("users");
        Assert.Empty(none.EnumerateArray());
        await AssertRefusedAsync(await admin.PostAsJsonAsync(new Uri("/api/v1/users/search", UriKind.Relative), new { email = "no" }), HttpStatusCode.BadRequest, "invalid_request", "email");

        var user = (await BodyOfAsync(await admin.GetAsync(UserAt(id)))).GetProperty("user");
        Assert.Equal(email, user.GetProperty("email").GetString());
        Assert.Equal("00000000-0000-0000-0000-000000000001", user.GetProperty("tenant_id").GetString());
        Assert.True(user.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task APerson_IsRenamed_AndANameThatIsNotAStringIsRefused()
    {
        var admin = AdminClient(AdminKey);
        var (id, _) = await NewPersonAsync();

        var renamed = await admin.PutAsJsonAsync(UserAt(id), new { name = "A New Name" });
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        Assert.Equal("A New Name", (await BodyOfAsync(await admin.GetAsync(UserAt(id)))).GetProperty("user").GetProperty("name").GetString());

        await AssertRefusedAsync(await admin.PutAsJsonAsync(UserAt(id), new { name = 7 }), HttpStatusCode.BadRequest, "invalid_request", "name");

        var cleared = await admin.PutAsJsonAsync(UserAt(id), new { name = string.Empty });
        Assert.False((await BodyOfAsync(cleared)).GetProperty("user").TryGetProperty("name", out _));
    }

    [Fact]
    public async Task APerson_IsDeleted_WithWhatTheyWereGiven()
    {
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var accessToken = (await ExchangeAsync(application, code, pkce.Verifier)).Body.GetProperty("access_token").GetString()!;
        string id;
        using (var scope = server.Services.CreateScope())
        {
            id = (await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(address))!.Id.ToString();
        }

        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync(UserAt(id))).StatusCode);

        await AssertRefusedAsync(await admin.GetAsync(UserAt(id)), HttpStatusCode.NotFound, "not_found");
        await AssertRefusedAsync(await admin.DeleteAsync(UserAt(id)), HttpStatusCode.NotFound, "not_found");
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(accessToken)).StatusCode);
        await AssertRefusedAsync(await admin.GetAsync(UserAt("not-an-id")), HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task SigningOutEverywhere_EndsEverySession_AndEverythingThePersonWasGiven()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var tokens = await ExchangeAsync(application, await SignInAndGetCodeAsync(browser, application, address, pkce), pkce.Verifier);
        var accessToken = tokens.Body.GetProperty("access_token").GetString()!;

        // Another device is signed in too.
        var elsewhere = server.CreateClient(followRedirects: false);
        await SignInAndGetCodeAsync(elsewhere, application, address, Pkce.New());

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/logout", UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await server.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((await BodyOfAsync(response)).GetProperty("success").GetBoolean());
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(accessToken)).StatusCode);
        Assert.Equal("invalid_grant", (await RefreshAsync(application, tokens.Body.GetProperty("refresh_token").GetString()!)).Body.GetProperty("error").GetString());
        foreach (var device in new[] { browser, elsewhere })
        {
            var again = await device.GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge), UriKind.Relative));
            Assert.StartsWith("/login?flow=", again.Headers.Location!.OriginalString, StringComparison.Ordinal);
        }

        // The token that made the call is spent with the rest.
        using var twice = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/logout", UriKind.Relative));
        twice.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        await AssertRefusedAsync(await server.Client.SendAsync(twice), HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task ARefreshToken_IsUsedOnce()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var tokens = await ExchangeAsync(application, await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce), pkce.Verifier);
        var refresh = tokens.Body.GetProperty("refresh_token").GetString()!;

        var first = await RefreshAsync(application, refresh);
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.NotEqual(refresh, first.Body.GetProperty("refresh_token").GetString());

        var again = await RefreshAsync(application, refresh);
        Assert.Equal(HttpStatusCode.BadRequest, again.Status);
        Assert.Equal("invalid_grant", again.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task SigningOutEverywhere_NeedsAPersonsToken()
    {
        var none = await server.Client.PostAsync(new Uri("/api/v1/logout", UriKind.Relative), null);
        await AssertRefusedAsync(none, HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Contains("Bearer", none.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);

        using var garbage = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/logout", UriKind.Relative));
        garbage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not.a.token");
        await AssertRefusedAsync(await server.Client.SendAsync(garbage), HttpStatusCode.Unauthorized, "unauthorized");

        // An application's own token is not a person's.
        var admin = AdminClient(AdminKey);
        var created = await RegisterClientAsync(admin, new { name = "machine", grant_types = ClientCredentials, scopes = Openid });
        var credentials = created.GetProperty("credentials");
        var token = await BodyOfAsync(await TokenAsync(credentials.GetProperty("client_id").GetString()!, credentials.GetProperty("client_secret").GetString()!));
        using var machine = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/v1/logout", UriKind.Relative));
        machine.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.GetProperty("access_token").GetString());
        await AssertRefusedAsync(await server.Client.SendAsync(machine), HttpStatusCode.Unauthorized, "unauthorized");
    }
}
