using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Authway.Data;
using Authway.Server.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authway.Server.Tests;

/// <summary>
/// A person is mailed a link to prove their address or to choose a new password. A request for a message answers
/// the same for every address, and what the link does is done once.
/// </summary>
public abstract partial class ServerTests
{
    private static readonly Uri SendVerification = new("/api/v1/email/send-verification", UriKind.Relative);
    private static readonly Uri ForgotPassword = new("/api/v1/email/forgot-password", UriKind.Relative);
    private static readonly Uri ResetPassword = new("/api/v1/email/reset-password", UriKind.Relative);

    private const string NewPassword = "A-new-password-1";

    private HttpClient RecordingClient(MailRecorder recorder) =>
        server.CreateClientWith(new Dictionary<string, string?>(), services => services.Replace(ServiceDescriptor.Singleton<IMailSender>(recorder)));

    /// <summary>The mail is handed over after the answer has gone, so a test waits for it as long as it takes a queue to be read.</summary>
    private static async Task<(string Recipient, Message Message)> MailedAsync(MailRecorder recorder, int count = 1)
    {
        for (var waited = 0; waited < 100 && recorder.Sent.Count < count; waited++)
        {
            await Task.Delay(50);
        }

        Assert.True(recorder.Sent.Count >= count, $"expected {count} message(s), {recorder.Sent.Count} were sent");
        return recorder.Sent.ToArray()[count - 1];
    }

    /// <summary>Gives the queue time to send what it would have sent, to show that it sent nothing.</summary>
    private static async Task AssertNothingMailedAsync(MailRecorder recorder, int expected = 0)
    {
        await Task.Delay(750);
        Assert.Equal(expected, recorder.Sent.Count);
    }

    private static string TokenOf(Message message)
    {
        var link = Regex.Match(message.Text, @"https?://\S+[?&]token=(?<token>[^\s&]+)", RegexOptions.None, TimeSpan.FromSeconds(1));
        Assert.True(link.Success, message.Text);
        return Uri.UnescapeDataString(link.Groups["token"].Value);
    }

    /// <summary>The form a link's token is kept in: its SHA-256, in hexadecimal.</summary>
    private static string HashOf(string token) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

    private static Uri ResetCheck(string token) => new($"/api/v1/email/verify-reset-token?token={Uri.EscapeDataString(token)}", UriKind.Relative);

    private static Uri VerifyAt(string token) => new($"/api/v1/email/verify?token={Uri.EscapeDataString(token)}", UriKind.Relative);

    private async Task<string> PersonWithoutVerifiedAddressAsync()
    {
        using var scope = server.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var address = $"unverified-{Guid.NewGuid():N}@example.test";
        var created = await users.CreateAsync(new ApplicationUser { UserName = address, Email = address, EmailConfirmed = false }, Password);
        Assert.True(created.Succeeded);
        return address;
    }

    private async Task<bool> PasswordWorksAsync(string address, string password)
    {
        using var scope = server.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return await users.CheckPasswordAsync((await users.FindByEmailAsync(address))!, password);
    }

    [Fact]
    public async Task APasswordResetLink_ChoosesANewPassword_Once()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        var asked = await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        Assert.Equal(HttpStatusCode.OK, asked.StatusCode);
        var (recipient, message) = await MailedAsync(recorder);
        Assert.Equal(address, recipient);
        var token = TokenOf(message);
        Assert.Contains("/reset-password?token=", message.Text, StringComparison.Ordinal);

        var checkedLink = await BodyOfAsync(await client.GetAsync(ResetCheck(token)));
        Assert.True(checkedLink.GetProperty("valid").GetBoolean());
        Assert.Equal(8, checkedLink.GetProperty("password_min_length").GetInt32());

        // A password that is too short is refused and does not use the link up.
        var tooShort = await client.PostAsJsonAsync(ResetPassword, new { token, new_password = "short" });
        await AssertRefusedAsync(tooShort, HttpStatusCode.BadRequest, "password_too_short", "new_password");
        Assert.True(await PasswordWorksAsync(address, Password));

        var reset = await client.PostAsJsonAsync(ResetPassword, new { token, new_password = NewPassword });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.False(await PasswordWorksAsync(address, Password));
        Assert.True(await PasswordWorksAsync(address, NewPassword));

        // The link was spent: it neither checks out nor chooses another password.
        await AssertRefusedAsync(await client.GetAsync(ResetCheck(token)), HttpStatusCode.BadRequest, "token_expired");
        await AssertRefusedAsync(await client.PostAsJsonAsync(ResetPassword, new { token, new_password = "Another-password-2" }), HttpStatusCode.BadRequest, "token_expired");
        Assert.True(await PasswordWorksAsync(address, NewPassword));
    }

    [Fact]
    public async Task APasswordReset_EndsWhatThePersonWasGiven_AndProvesTheAddress()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var pkce = Pkce.New();
        var code = await SignInAndGetCodeAsync(server.CreateClient(followRedirects: false), application, address, pkce);
        var tokens = (await ExchangeAsync(application, code, pkce.Verifier)).Body;
        var id = await PersonIdAsync(address);

        using (var scope = server.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var person = (await users.FindByIdAsync(id))!;
            person.EmailConfirmed = false;
            await users.UpdateAsync(person);
        }

        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);
        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        var token = TokenOf((await MailedAsync(recorder)).Message);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(ResetPassword, new { token, new_password = NewPassword })).StatusCode);

        // Whoever held the sessions may not know the new password.
        var renewed = await RefreshAsync(application, tokens.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, renewed.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserinfoAsync(tokens.GetProperty("access_token").GetString()!)).StatusCode);

        // The link reached the address, which proves it as a verification mail would.
        using var check = server.Services.CreateScope();
        Assert.True((await check.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByIdAsync(id))!.EmailConfirmed);
    }

    [Fact]
    public async Task ARequestForAMessage_IsAnsweredTheSame_ForAnAddressWithNoAccount()
    {
        var (_, known) = await RegisterApplicationAndPersonAsync();
        using (var scope = server.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var person = (await users.FindByEmailAsync(known))!;
            person.EmailConfirmed = true;
            await users.UpdateAsync(person);
        }

        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        var forKnown = await client.PostAsJsonAsync(ForgotPassword, new { email = known });
        var forNobody = await client.PostAsJsonAsync(ForgotPassword, new { email = $"nobody-{Guid.NewGuid():N}@example.test" });
        Assert.Equal(HttpStatusCode.OK, forNobody.StatusCode);
        Assert.Equal(await forKnown.Content.ReadAsStringAsync(), await forNobody.Content.ReadAsStringAsync());

        var verifiedAsked = await client.PostAsJsonAsync(SendVerification, new { email = known });
        var nobodyAsked = await client.PostAsJsonAsync(SendVerification, new { email = $"nobody-{Guid.NewGuid():N}@example.test" });
        Assert.Equal(await verifiedAsked.Content.ReadAsStringAsync(), await nobodyAsked.Content.ReadAsStringAsync());

        // One message went out: the reset for the account that exists. An address that is verified already is sent no verification.
        var (recipient, _) = await MailedAsync(recorder);
        Assert.Equal(known, recipient);
        await AssertNothingMailedAsync(recorder, expected: 1);
    }

    [Fact]
    public async Task AnApplicationThatIsNamed_MustExist_AndAnAddressMustBeOne()
    {
        var client = RecordingClient(new MailRecorder());
        foreach (var path in new[] { SendVerification, ForgotPassword })
        {
            await AssertRefusedAsync(await client.PostAsJsonAsync(path, new { email = "someone@example.test", client_id = $"none-{Guid.NewGuid():N}" }), HttpStatusCode.BadRequest, "unknown_client", "client_id");
            await AssertRefusedAsync(await client.PostAsJsonAsync(path, new { email = "not-an-address" }), HttpStatusCode.BadRequest, "invalid_request", "email");
        }
    }

    [Fact]
    public async Task AnAddressIsVerified_ByTheLinkItWasMailed()
    {
        var address = await PersonWithoutVerifiedAddressAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(SendVerification, new { email = address })).StatusCode);
        var (_, message) = await MailedAsync(recorder);
        Assert.Contains("/verify-email?token=", message.Text, StringComparison.Ordinal);
        var token = TokenOf(message);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(VerifyAt(token))).StatusCode);
        using (var scope = server.Services.CreateScope())
        {
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(address))!.EmailConfirmed);
        }

        // A mail client that follows the link ahead of the person does no harm: following it again says the same.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(VerifyAt(token))).StatusCode);
        await AssertRefusedAsync(await client.GetAsync(VerifyAt("not-a-link-we-sent")), HttpStatusCode.NotFound, "invalid_token");
        await AssertRefusedAsync(await client.GetAsync(new Uri("/api/v1/email/verify", UriKind.Relative)), HttpStatusCode.BadRequest, "invalid_request");

        // A reset link is not a verification link.
        var other = await PersonWithoutVerifiedAddressAsync();
        await client.PostAsJsonAsync(ForgotPassword, new { email = other });
        var resetToken = TokenOf((await MailedAsync(recorder, 2)).Message);
        await AssertRefusedAsync(await client.GetAsync(VerifyAt(resetToken)), HttpStatusCode.NotFound, "invalid_token");
    }

    [Fact]
    public async Task ALinkThatHasExpired_IsRefused()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);
        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        var token = TokenOf((await MailedAsync(recorder)).Message);

        using (var scope = server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
            var hash = HashOf(token);
            await db.EmailTokens.Where(t => t.TokenHash == hash).ExecuteUpdateAsync(set => set.SetProperty(t => t.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)));
        }

        await AssertRefusedAsync(await client.GetAsync(ResetCheck(token)), HttpStatusCode.BadRequest, "token_expired");
        await AssertRefusedAsync(await client.PostAsJsonAsync(ResetPassword, new { token, new_password = NewPassword }), HttpStatusCode.BadRequest, "token_expired");
        Assert.True(await PasswordWorksAsync(address, Password));
        await AssertRefusedAsync(await client.GetAsync(ResetCheck("not-a-link-we-sent")), HttpStatusCode.BadRequest, "invalid_token");
    }

    [Fact]
    public async Task ASuspendedAccount_IsSentNoLink_AndALinkSentBeforeIsRefusedForIt()
    {
        var admin = AdminClient(AdminKey);
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var id = await PersonIdAsync(address);
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        var token = TokenOf((await MailedAsync(recorder)).Message);

        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(UserAt(id), new { active = false })).StatusCode);

        // The answer is the one any address gets, and nothing is sent.
        var asked = await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        Assert.Equal(HttpStatusCode.OK, asked.StatusCode);
        await AssertNothingMailedAsync(recorder, expected: 1);

        // Holding the link proves the address, so the refusal says why; the password is kept.
        await AssertRefusedAsync(await client.GetAsync(ResetCheck(token)), HttpStatusCode.Forbidden, "account_suspended");
        await AssertRefusedAsync(await client.PostAsJsonAsync(ResetPassword, new { token, new_password = NewPassword }), HttpStatusCode.Forbidden, "account_suspended");
        Assert.True(await PasswordWorksAsync(address, Password));

        // The link was not spent by being refused: lifted, it works.
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(UserAt(id), new { active = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(ResetPassword, new { token, new_password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task AnAccount_IsSentAFewMessages_InAShortWhile()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        for (var asked = 0; asked < 5; asked++)
        {
            var answer = await client.PostAsJsonAsync(ForgotPassword, new { email = address });
            Assert.Equal(HttpStatusCode.OK, answer.StatusCode);
        }

        await MailedAsync(recorder, 3);
        await AssertNothingMailedAsync(recorder, expected: 3);
    }

    [Fact]
    public async Task ALinkIsKeptOnlyAsItsHash()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);
        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        var token = TokenOf((await MailedAsync(recorder)).Message);

        using var scope = server.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
        var id = Guid.Parse(await PersonIdAsync(address));
        var stored = await db.EmailTokens.AsNoTracking().Where(t => t.UserId == id).ToListAsync();
        var link = Assert.Single(stored);
        Assert.NotEqual(token, link.TokenHash);
        Assert.Equal(HashOf(token), link.TokenHash);
        Assert.Equal(EmailToken.PasswordReset, link.Purpose);
        Assert.InRange(link.ExpiresAt - link.CreatedAt, TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(61));
    }

    [Fact]
    public async Task ALink_GoesToTheConfiguredScreens_NotToTheAddressTheRequestNames()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = server.CreateClientWith(
            new Dictionary<string, string?> { ["Authway:Ui:BaseUrl"] = "https://login.example.test/" },
            services => services.Replace(ServiceDescriptor.Singleton<IMailSender>(recorder)));

        // Anyone can ask for a link for anyone's address, and say whatever they like the server is called.
        using var request = new HttpRequestMessage(HttpMethod.Post, ForgotPassword) { Content = JsonContent.Create(new { email = address }) };
        request.Headers.Host = "evil.example.test";
        request.Headers.Add("X-Forwarded-Host", "evil.example.test");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);

        var (_, message) = await MailedAsync(recorder);
        Assert.StartsWith("https://login.example.test/reset-password?token=", Regex.Match(message.Text, @"https?://\S+").Value, StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example.test", message.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResetLink_SpendsTheOthersAskedForBefore_AndSoDoesChoosingAPasswordAnotherWay()
    {
        var (_, address) = await RegisterApplicationAndPersonAsync();
        var recorder = new MailRecorder();
        var client = RecordingClient(recorder);

        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        await client.PostAsJsonAsync(ForgotPassword, new { email = address });
        var first = TokenOf((await MailedAsync(recorder, 1)).Message);
        var second = TokenOf((await MailedAsync(recorder, 2)).Message);
        Assert.NotEqual(first, second);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(ResetPassword, new { token = second, new_password = NewPassword })).StatusCode);

        // The link asked for first was good for an hour, and is not any more: whoever read the old mail cannot use it.
        await AssertRefusedAsync(await client.GetAsync(ResetCheck(first)), HttpStatusCode.BadRequest, "token_expired");
        await AssertRefusedAsync(await client.PostAsJsonAsync(ResetPassword, new { token = first, new_password = "Another-password-2" }), HttpStatusCode.BadRequest, "token_expired");
        Assert.True(await PasswordWorksAsync(address, NewPassword));
    }
}
