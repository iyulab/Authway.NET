using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Authway.Server.Tests;

/// <summary>A signed-in person reads their own profile and chooses another password; every session opened with the old one ends.</summary>
public abstract partial class ServerTests
{
    private static readonly Uri OwnProfile = new("/api/v1/profile/me", UriKind.Relative);
    private static readonly Uri OwnPassword = new("/api/v1/users/password", UriKind.Relative);

    private async Task<JsonElement> SignInTokensAsync(string application, string address)
    {
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        return (await ExchangeAsync(application, code, pkce.Verifier)).Body;
    }

    private async Task<HttpResponseMessage> AsAsync(string accessToken, HttpMethod method, Uri uri, object? body = null)
    {
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await server.Client.SendAsync(request);
    }

    [Fact]
    public async Task APerson_ReadsTheirOwnProfile_WithTheirOwnToken()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var tokens = await SignInTokensAsync(application, address);

        var profile = await BodyOfAsync(await AsAsync(tokens.GetProperty("access_token").GetString()!, HttpMethod.Get, OwnProfile));
        Assert.Equal(await PersonIdAsync(address), profile.GetProperty("id").GetString());
        Assert.Equal(address, profile.GetProperty("email").GetString());
        Assert.Equal("Person Under Test", profile.GetProperty("name").GetString());
        Assert.False(profile.GetProperty("email_verified").GetBoolean());
        Assert.True(profile.GetProperty("has_password").GetBoolean());
        Assert.True(DateTimeOffset.TryParse(profile.GetProperty("created_at").GetString(), out _));

        await AssertRefusedAsync(await server.Client.GetAsync(OwnProfile), HttpStatusCode.Unauthorized, "unauthorized");
        await AssertRefusedAsync(await AsAsync("not-a-token", HttpMethod.Get, OwnProfile), HttpStatusCode.Unauthorized, "unauthorized");

        // A token an application holds for itself is not a person's.
        var (clientId, secret, _) = await RegisterMachineAsync(AdminClient(AdminKey));
        var machine = await MachineTokenAsync(clientId, secret);
        await AssertRefusedAsync(await AsAsync(machine.Body.GetProperty("access_token").GetString()!, HttpMethod.Get, OwnProfile), HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task APasswordChange_NeedsTheCurrentPassword_AndTheRule()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var token = (await SignInTokensAsync(application, address)).GetProperty("access_token").GetString()!;

        await AssertRefusedAsync(await AsAsync(token, HttpMethod.Post, OwnPassword, new { current_password = "not-the-password", new_password = "A-new-password-1" }), HttpStatusCode.BadRequest, "invalid_current_password", "current_password");
        await AssertRefusedAsync(await AsAsync(token, HttpMethod.Post, OwnPassword, new { new_password = "A-new-password-1" }), HttpStatusCode.BadRequest, "invalid_current_password", "current_password");
        await AssertRefusedAsync(await AsAsync(token, HttpMethod.Post, OwnPassword, new { current_password = Password }), HttpStatusCode.BadRequest, "invalid_request", "new_password");

        var tooShort = await AsAsync(token, HttpMethod.Post, OwnPassword, new { current_password = Password, new_password = "short" });
        await AssertRefusedAsync(tooShort, HttpStatusCode.BadRequest, "password_too_short", "new_password");
        Assert.Equal(8, (await BodyOfAsync(tooShort)).GetProperty("min_length").GetInt32());

        Assert.True(await PasswordWorksAsync(address, Password));
        await AssertRefusedAsync(await server.Client.PostAsJsonAsync(OwnPassword, new { current_password = Password, new_password = "A-new-password-1" }), HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task APasswordChange_EndsEverySession()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var here = await SignInTokensAsync(application, address);
        var elsewhere = await SignInTokensAsync(application, address);

        // A link to choose a password asked for before the change is moot after it.
        var recorder = new MailRecorder();
        var mailClient = RecordingClient(recorder);
        await mailClient.PostAsJsonAsync(ForgotPassword, new { email = address });
        var link = TokenOf((await MailedAsync(recorder)).Message);
        Assert.Equal(HttpStatusCode.OK, (await UserinfoAsync(elsewhere.GetProperty("access_token").GetString()!)).StatusCode);

        var changed = await AsAsync(here.GetProperty("access_token").GetString()!, HttpMethod.Post, OwnPassword, new { current_password = Password, new_password = "A-new-password-1" });
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        Assert.Equal("all", (await BodyOfAsync(changed)).GetProperty("sessions_ended").GetString());

        // What the person was given, in this session and in the other, stops working: two sign-ins to the same
        // application share what the person agreed to, so one cannot be told from the other.
        foreach (var tokens in new[] { here, elsewhere })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await UserinfoAsync(tokens.GetProperty("access_token").GetString()!)).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(application, tokens.GetProperty("refresh_token").GetString()!)).Status);
        }

        Assert.False(await PasswordWorksAsync(address, Password));
        Assert.True(await PasswordWorksAsync(address, "A-new-password-1"));
        await AssertRefusedAsync(await mailClient.GetAsync(ResetCheck(link)), HttpStatusCode.BadRequest, "token_expired");
    }
}
