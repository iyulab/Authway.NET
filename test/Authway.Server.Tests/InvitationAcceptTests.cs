using System.Net;
using System.Net.Http.Json;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Server.Tests;

/// <summary>The person invited follows the mailed link, sees the invitation and chooses a password.</summary>
public abstract partial class ServerTests
{
    private static Uri ByToken(string token, string rest = "") => new($"/api/v1/invitations/token/{Uri.EscapeDataString(token)}{rest}", UriKind.Relative);

    private static readonly Uri AcceptAt = new("/api/v1/invitations/accept", UriKind.Relative);

    /// <summary>Invites an address and returns it with the token of the link that was mailed.</summary>
    private static async Task<(string Id, string Email, string Token)> InviteAsync(HttpClient admin, MailRecorder recorder, object? extra = null)
    {
        var email = NewAddress();
        var response = await admin.PostAsJsonAsync(Invitations, MergeEmail(email, extra));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var id = (await BodyOfAsync(response)).GetProperty("invitation").GetProperty("id").GetString()!;
        var mail = recorder.Sent.Last(m => m.Recipient == email).Message;
        return (id, email, TokenIn(mail));
    }

    private static Dictionary<string, object?> MergeEmail(string email, object? extra)
    {
        var merged = extra?.GetType().GetProperties().ToDictionary(p => p.Name, p => p.GetValue(extra)) ?? [];
        merged["email"] = email;
        return merged;
    }

    [Fact]
    public async Task TheLinkShowsTheInvitation_AndAcceptingItMakesAnAccountThatCanSignIn()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        var (_, email, token) = await InviteAsync(admin, recorder, new { message = "Welcome aboard" });

        var shown = await BodyOfAsync(await server.Client.GetAsync(ByToken(token)));
        var invitation = shown.GetProperty("invitation");
        Assert.Equal(email, invitation.GetProperty("email").GetString());
        Assert.Equal("Default", invitation.GetProperty("tenant_name").GetString());
        Assert.Equal("Welcome aboard", invitation.GetProperty("message").GetString());
        Assert.Equal(8, shown.GetProperty("password_min_length").GetInt32());

        var accepted = await server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password, name = "Person Invited" });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        var user = (await BodyOfAsync(accepted)).GetProperty("user");
        Assert.Equal(email, user.GetProperty("email").GetString());

        // The address is proven by the link, and the password is the one chosen.
        using (var scope = server.Services.CreateScope())
        {
            var account = await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email);
            Assert.True(account!.EmailConfirmed);
            Assert.Equal("Person Invited", account.DisplayName);
        }

        var application = await RegisterApplicationAsync();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, email, Pkce.New());
        Assert.False(string.IsNullOrEmpty(code));
    }

    [Fact]
    public async Task AnAcceptedInvitation_CannotBeAcceptedAgain_NorShown()
    {
        var recorder = new MailRecorder();
        var (_, _, token) = await InviteAsync(AdminClientRecording(recorder), recorder);
        Assert.Equal(HttpStatusCode.OK, (await server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password })).StatusCode);

        await AssertRefusedAsync(await server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password }), HttpStatusCode.BadRequest, "invitation_not_accepted");
        var shown = await server.Client.GetAsync(ByToken(token));
        await AssertRefusedAsync(shown, HttpStatusCode.BadRequest, "invitation_not_acceptable");
        Assert.Equal("accepted", (await BodyOfAsync(shown)).GetProperty("invitation_status").GetString());
    }

    [Fact]
    public async Task AShortPassword_IsRefusedWithTheLeastLength_AndTheInvitationIsLeftAsItWas()
    {
        var recorder = new MailRecorder();
        var (_, email, token) = await InviteAsync(AdminClientRecording(recorder), recorder);

        var refused = await server.Client.PostAsJsonAsync(AcceptAt, new { token, password = "short" });

        await AssertRefusedAsync(refused, HttpStatusCode.BadRequest, "password_too_short", "password");
        Assert.Equal(8, (await BodyOfAsync(refused)).GetProperty("min_length").GetInt32());
        using (var scope = server.Services.CreateScope())
        {
            Assert.Null(await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email));
        }

        Assert.Equal(HttpStatusCode.OK, (await server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password })).StatusCode);
    }

    [Fact]
    public async Task ALinkThatIsUnknown_Revoked_Resent_OrExpired_DoesNotWork()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);

        await AssertRefusedAsync(await server.Client.GetAsync(ByToken("not-a-token")), HttpStatusCode.NotFound, "invalid_token");
        await AssertRefusedAsync(await server.Client.PostAsJsonAsync(AcceptAt, new { token = "not-a-token", password = Password }), HttpStatusCode.BadRequest, "invitation_not_accepted");
        await AssertRefusedAsync(await server.Client.PostAsJsonAsync(AcceptAt, new { password = Password }), HttpStatusCode.BadRequest, "invalid_request", "token");

        var (revokedId, _, revoked) = await InviteAsync(admin, recorder);
        await admin.DeleteAsync(InvitationAt(revokedId));
        await AssertRefusedAsync(await server.Client.GetAsync(ByToken(revoked)), HttpStatusCode.BadRequest, "invitation_not_acceptable");

        var (resentId, _, old) = await InviteAsync(admin, recorder);
        await admin.PostAsync(InvitationAt(resentId, "/resend"), null);
        var fresh = TokenIn(recorder.Sent.Last().Message);
        await AssertRefusedAsync(await server.Client.GetAsync(ByToken(old)), HttpStatusCode.NotFound, "invalid_token");
        Assert.Equal(HttpStatusCode.OK, (await server.Client.GetAsync(ByToken(fresh))).StatusCode);

        var (expiredId, _, expired) = await InviteAsync(admin, recorder);
        using (var scope = server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
            (await db.Invitations.FindAsync(Guid.Parse(expiredId)))!.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        var shown = await server.Client.GetAsync(ByToken(expired));
        await AssertRefusedAsync(shown, HttpStatusCode.BadRequest, "invitation_not_acceptable");
        Assert.Equal("expired", (await BodyOfAsync(shown)).GetProperty("invitation_status").GetString());
        await AssertRefusedAsync(await server.Client.PostAsJsonAsync(AcceptAt, new { token = expired, password = Password }), HttpStatusCode.BadRequest, "invitation_not_accepted");
    }

    [Fact]
    public async Task TwoAnswersToTheSameLink_MakeOneAccount()
    {
        var recorder = new MailRecorder();
        var (_, email, token) = await InviteAsync(AdminClientRecording(recorder), recorder);

        var answers = await Task.WhenAll(
            server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password }),
            server.Client.PostAsJsonAsync(AcceptAt, new { token, password = Password }));

        Assert.Single(answers, a => a.StatusCode == HttpStatusCode.OK);
        Assert.Single(answers, a => a.StatusCode == HttpStatusCode.BadRequest);
        using var scope = server.Services.CreateScope();
        Assert.Equal(1, scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().Users.Count(u => u.Email == email));
    }

    [Fact]
    public async Task AnInvitationForAnApplication_ShowsIt()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        var app = (await RegisterClientAsync(admin, new { name = "Named app", client_uri = "https://app.example.test/", grant_types = ClientCredentials, scopes = Openid })).GetProperty("client");
        var (_, _, token) = await InviteAsync(admin, recorder, new { client_id = app.GetProperty("client_id").GetString() });

        var client = (await BodyOfAsync(await server.Client.GetAsync(ByToken(token)))).GetProperty("invitation").GetProperty("client");

        Assert.Equal("Named app", client.GetProperty("name").GetString());
        Assert.Equal("https://app.example.test/", client.GetProperty("client_uri").GetString());
    }

    [Fact]
    public async Task SigningInWithAnotherProvider_IsNotOffered()
    {
        var browser = server.CreateClient(followRedirects: false);

        var social = await browser.GetAsync(ByToken("some-token", "/social/google"));
        Assert.Equal(HttpStatusCode.Redirect, social.StatusCode);
        Assert.Contains("error=provider_unavailable", social.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.Contains("token=some-token", social.Headers.Location.OriginalString, StringComparison.Ordinal);

        await AssertRefusedAsync(await browser.GetAsync(new Uri($"/api/v1/invitations/receipts/{Guid.NewGuid()}", UriKind.Relative)), HttpStatusCode.NotFound, "not_found");
    }
}
