using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Authway.Server.Tests;

/// <summary>
/// An administrator suspends an account or turns an application off, and what they had stops working; the tokens
/// name the resource servers they are for.
/// </summary>
public abstract partial class ServerTests
{
    private const string Api = "https://api.example.test";

    // A public application with a web redirect address names the origins it is served from, as the API asks when it is changed.
    private static readonly string[] AppOrigin = ["https://app.example.test"];

    private async Task<string> PersonIdAsync(string address)
    {
        using var scope = server.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(address))!.Id.ToString();
    }

    private async Task<string> ApplicationIdAsync(string clientId)
    {
        using var scope = server.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        return (await applications.GetIdAsync((await applications.FindByClientIdAsync(clientId))!))!;
    }

    private async Task RegisterForResourceServersAsync(string clientId, params string[] audience)
    {
        using var scope = server.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = (await applications.FindByClientIdAsync(clientId))!;
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        descriptor.Properties["audience"] = JsonSerializer.SerializeToElement(audience);
        await applications.UpdateAsync(application, descriptor);
    }

    private async Task<HttpResponseMessage> UserinfoAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/connect/userinfo", UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await server.Client.SendAsync(request);
    }

    private static async Task<(string ClientId, string Secret, string Id)> RegisterMachineAsync(HttpClient admin, params string[] audience)
    {
        var created = await RegisterClientAsync(admin, new
        {
            tenant_id = TenantId,
            name = $"machine-{Guid.NewGuid():N}"[..20],
            @public = false,
            grant_types = ClientCredentials,
            scopes = Openid,
            audience,
        });
        return (created.GetProperty("client").GetProperty("client_id").GetString()!, created.GetProperty("credentials").GetProperty("client_secret").GetString()!, created.GetProperty("client").GetProperty("id").GetString()!);
    }

    private Task<(HttpStatusCode Status, JsonElement Body)> MachineTokenAsync(string clientId, string secret, string? audience = null) =>
        TokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }.Concat(audience is null ? [] : [new KeyValuePair<string, string>("audience", audience)]).ToDictionary());

    [Fact]
    public async Task APictureAddress_IsKept_ReadBack_AndCleared()
    {
        var admin = AdminClient(AdminKey);
        var (id, _) = await NewPersonAsync();

        var set = await admin.PutAsJsonAsync(UserAt(id), new { avatar_url = "https://img.example.test/a.png" });
        Assert.Equal("https://img.example.test/a.png", (await BodyOfAsync(set)).GetProperty("user").GetProperty("avatar_url").GetString());
        Assert.Equal("https://img.example.test/a.png", (await BodyOfAsync(await admin.GetAsync(UserAt(id)))).GetProperty("user").GetProperty("avatar_url").GetString());

        await AssertRefusedAsync(await admin.PutAsJsonAsync(UserAt(id), new { avatar_url = 7 }), HttpStatusCode.BadRequest, "invalid_request", "avatar_url");
        await AssertRefusedAsync(await admin.PutAsJsonAsync(UserAt(id), new { avatar_url = new string('a', 3000) }), HttpStatusCode.BadRequest, "invalid_request", "avatar_url");

        var cleared = await admin.PutAsJsonAsync(UserAt(id), new { avatar_url = string.Empty });
        Assert.Equal(string.Empty, (await BodyOfAsync(cleared)).GetProperty("user").GetProperty("avatar_url").GetString());
    }

    [Fact]
    public async Task ASuspendedAccount_StopsWorking_AndWorksAgainWhenTheSuspensionIsLifted()
    {
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var tokens = (await ExchangeAsync(application, code, pkce.Verifier)).Body;
        var id = await PersonIdAsync(address);
        Assert.Equal(HttpStatusCode.OK, (await UserinfoAsync(tokens.GetProperty("access_token").GetString()!)).StatusCode);

        var suspended = await BodyOfAsync(await admin.PutAsJsonAsync(UserAt(id), new { active = false }));
        Assert.False(suspended.GetProperty("user").GetProperty("active").GetBoolean());

        // What the person had stops working.
        var renewed = await RefreshAsync(application, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, renewed.Status);
        Assert.Equal("invalid_grant", renewed.Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserinfoAsync(tokens.GetProperty("access_token").GetString()!)).StatusCode);

        // A wrong password says nothing of the account; the right one is refused for it.
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var wrong = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = "not-the-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        await AssertRefusedAsync(await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password }), HttpStatusCode.Forbidden, "account_suspended");

        // Written down, both ways.
        var recorded = await BodyOfAsync(await admin.GetAsync(AuditAt($"logs?action=user.suspended&resource_id={id}")));
        Assert.Equal(1, recorded.GetProperty("logs").GetArrayLength());

        var lifted = await BodyOfAsync(await admin.PutAsJsonAsync(UserAt(id), new { active = true }));
        Assert.True(lifted.GetProperty("user").GetProperty("active").GetBoolean());
        Assert.Equal(1, (await BodyOfAsync(await admin.GetAsync(AuditAt($"logs?action=user.reactivated&resource_id={id}")))).GetProperty("logs").GetArrayLength());
        Assert.False(string.IsNullOrEmpty(await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, Pkce.New())));
        await AssertRefusedAsync(await admin.PutAsJsonAsync(UserAt(id), new { active = "no" }), HttpStatusCode.BadRequest, "invalid_request", "active");
    }

    [Fact]
    public async Task AnApplicationThatIsTurnedOff_SignsNoOneIn_IssuesNothing_AndKeepsNoTokenInForce()
    {
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var applicationId = await ApplicationIdAsync(application);
        var browser = server.CreateClient(followRedirects: false);
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(browser, application, address, pkce);
        var tokens = (await ExchangeAsync(application, code, pkce.Verifier)).Body;
        var underway = await StartAsync(server.CreateClient(followRedirects: false), application, Pkce.New().Challenge);
        var (machine, secret, machineId) = await RegisterMachineAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await MachineTokenAsync(machine, secret)).Status);

        var turnedOff = await admin.PutAsJsonAsync(ClientAt(applicationId), new { active = false, allowed_origins = AppOrigin });
        Assert.False((await BodyOfAsync(turnedOff)).GetProperty("client").GetProperty("active").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(ClientAt(machineId), new { active = false })).StatusCode);

        // A new sign-in is handed an error, not a form.
        var started = await server.CreateClient(followRedirects: false).GetAsync(new Uri(AuthorizeUrl(application, Pkce.New().Challenge), UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, started.StatusCode);
        Assert.StartsWith(Callback, started.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.Equal("unauthorized_client", HttpUtility.ParseQueryString(started.Headers.Location.Query)["error"]);
        // One already on the login screen does not get through.
        var late = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{underway}/password", UriKind.Relative), new { email = address, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, late.StatusCode);

        // No grant issues a token, and what it held is not accepted.
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(application, tokens.GetProperty("refresh_token").GetString()!)).Status);
        var refused = await MachineTokenAsync(machine, secret);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("unauthorized_client", refused.Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserinfoAsync(tokens.GetProperty("access_token").GetString()!)).StatusCode);

        // Turned on, it works again; the sessions it had do not come back.
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(ClientAt(applicationId), new { active = true, allowed_origins = AppOrigin })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(ClientAt(machineId), new { active = true })).StatusCode);
        Assert.False(string.IsNullOrEmpty(await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, Pkce.New())));
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(application, tokens.GetProperty("refresh_token").GetString()!)).Status);
        Assert.Equal(HttpStatusCode.OK, (await MachineTokenAsync(machine, secret)).Status);
    }

    [Fact]
    public async Task AnApplicationsTokens_AreForTheResourceServersItIsRegisteredFor_AsAList()
    {
        var admin = AdminClient(AdminKey);

        // A person's token: the application's resource server, and when they signed in.
        var (application, address) = await RegisterApplicationAndPersonAsync();
        await RegisterForResourceServersAsync(application, Api);
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var person = Claims((await ExchangeAsync(application, code, pkce.Verifier)).Body.GetProperty("access_token").GetString()!);
        Assert.Equal([Api], person.GetProperty("aud").EnumerateArray().Select(a => a.GetString()));
        Assert.Equal(JsonValueKind.Number, person.GetProperty("auth_time").ValueKind);

        // An application registered for none has a token for none.
        var (plain, plainAddress) = await RegisterApplicationAndPersonAsync();
        var plainPkce = Pkce.New();
        var bare = Claims((await ExchangeAsync(plain, await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), plain, plainAddress, plainPkce), plainPkce.Verifier)).Body.GetProperty("access_token").GetString()!);
        Assert.False(bare.TryGetProperty("aud", out _));

        // An application's own token: about the application, of its tenant, for the resource servers it is registered for or the one it names.
        var (machine, secret, _) = await RegisterMachineAsync(admin, Api, "https://billing.example.test");
        var all = Claims((await MachineTokenAsync(machine, secret)).Body.GetProperty("access_token").GetString()!);
        Assert.Equal([Api, "https://billing.example.test"], all.GetProperty("aud").EnumerateArray().Select(a => a.GetString()));
        Assert.Equal(machine, all.GetProperty("sub").GetString());
        Assert.Equal(TenantId, all.GetProperty("tenant_id").GetString());
        Assert.Equal("openid", all.GetProperty("scope").GetString());
        Assert.False(all.TryGetProperty("auth_time", out _));
        Assert.False(all.TryGetProperty("email", out _));

        var one = Claims((await MachineTokenAsync(machine, secret, Api)).Body.GetProperty("access_token").GetString()!);
        Assert.Equal([Api], one.GetProperty("aud").EnumerateArray().Select(a => a.GetString()));

        var refused = await MachineTokenAsync(machine, secret, "https://other.example.test");
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_request", refused.Body.GetProperty("error").GetString());
    }
}
