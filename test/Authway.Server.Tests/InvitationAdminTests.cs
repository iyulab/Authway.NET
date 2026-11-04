using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Authway.Data;
using Authway.Server.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authway.Server.Tests;

/// <summary>An administrator invites an address and the person is mailed a link; the invitation can be read, mailed again and revoked.</summary>
public abstract partial class ServerTests
{
    private static readonly Uri Invitations = new("/api/v1/invitations", UriKind.Relative);

    private static Uri InvitationAt(string id, string rest = "") => new($"/api/v1/invitations/{id}{rest}", UriKind.Relative);

    /// <summary>What a mail sender is asked to send, so that a test can read the mail the server would have sent.</summary>
    private sealed class MailRecorder : IMailSender
    {
        public ConcurrentQueue<(string Recipient, Message Message)> Sent { get; } = new();

        public bool Fails { get; set; }

        public Task SendAsync(string recipient, Message message, CancellationToken cancellationToken = default)
        {
            if (Fails)
            {
                throw new InvalidOperationException("the mail server is down");
            }

            Sent.Enqueue((recipient, message));
            return Task.CompletedTask;
        }
    }

    private HttpClient AdminClientRecording(MailRecorder recorder)
    {
        var client = server.CreateClientWith(
            new Dictionary<string, string?> { ["Authway:Admin:ApiKey"] = AdminKey },
            services => services.Replace(ServiceDescriptor.Singleton<IMailSender>(recorder)));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AdminKey);
        return client;
    }

    private static string NewAddress() => $"invited-{Guid.NewGuid():N}@example.test";

    private static string TokenIn(Message message)
    {
        var link = message.Text.Split('\n').First(l => l.Contains("/invitation/accept?token=", StringComparison.Ordinal)).Trim();
        return HttpUtility.ParseQueryString(new Uri(link).Query)["token"]!;
    }

    [Fact]
    public async Task AnInvitation_IsCreated_AndTheLinkIsMailedInTheLanguageAsked()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        var email = NewAddress();
        using var request = new HttpRequestMessage(HttpMethod.Post, Invitations) { Content = JsonContent.Create(new { email, message = "Welcome aboard", role = "admin" }) };
        request.Headers.AcceptLanguage.ParseAdd("ko-KR,ko;q=0.9,en;q=0.8");

        var response = await admin.SendAsync(request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await BodyOfAsync(response);
        var invitation = body.GetProperty("invitation");
        Assert.Equal("pending", invitation.GetProperty("status").GetString());
        Assert.Equal(email, invitation.GetProperty("email").GetString());
        Assert.False(invitation.TryGetProperty("role", out _), "an invitation gives no role");
        Assert.True(DateTimeOffset.Parse(invitation.GetProperty("expires_at").GetString()!, System.Globalization.CultureInfo.InvariantCulture) > DateTimeOffset.UtcNow.AddDays(6));

        var (recipient, mail) = Assert.Single(recorder.Sent);
        Assert.Equal(email, recipient);
        Assert.Contains("초대", mail.Subject, StringComparison.Ordinal);
        Assert.Contains("Welcome aboard", mail.Text, StringComparison.Ordinal);
        Assert.False(string.IsNullOrEmpty(TokenIn(mail)));
    }

    [Theory]
    [InlineData("ko", null, "초대")]
    [InlineData("ko-KR", null, "초대")]
    [InlineData("en", "ko-KR,ko;q=0.9", "Invitation to")]
    [InlineData(null, "ko-KR,ko;q=0.9", "초대")]
    [InlineData(null, null, "Invitation to")]
    [InlineData("", "ko", "초대")]
    public async Task TheCall_MayNameTheLanguageOfTheEmail_AndItBeatsTheHeader(string? locale, string? acceptLanguage, string subject)
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        using var request = new HttpRequestMessage(HttpMethod.Post, Invitations) { Content = JsonContent.Create(new { email = NewAddress(), locale }) };
        if (acceptLanguage is not null)
        {
            request.Headers.AcceptLanguage.ParseAdd(acceptLanguage);
        }

        Assert.Equal(HttpStatusCode.Created, (await admin.SendAsync(request)).StatusCode);

        Assert.Contains(subject, Assert.Single(recorder.Sent).Message.Subject, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("fr")]
    [InlineData("*")]
    [InlineData("ko, en")]
    public async Task ALanguageThereAreNoStringsFor_IsRefused_AndNothingIsCreatedOrMailed(string locale)
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);

        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = NewAddress(), locale }), HttpStatusCode.BadRequest, "invalid_request", "locale");
        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = NewAddress(), locale = 7 }), HttpStatusCode.BadRequest, "invalid_request", "locale");

        Assert.Empty(recorder.Sent);
    }

    [Fact]
    public async Task AResend_MayNameTheLanguage_AndNeedsNoBody()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        var id = await CreateInvitationAsync(admin);

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync(InvitationAt(id, "/resend"), new { locale = "ko" })).StatusCode);
        Assert.Contains("초대", recorder.Sent.Last().Message.Subject, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync(InvitationAt(id, "/resend"), null)).StatusCode);
        Assert.Contains("Invitation to", recorder.Sent.Last().Message.Subject, StringComparison.Ordinal);

        var sent = recorder.Sent.Count;
        await AssertRefusedAsync(await admin.PostAsJsonAsync(InvitationAt(id, "/resend"), new { locale = "fr" }), HttpStatusCode.BadRequest, "invalid_request", "locale");
        Assert.Equal(sent, recorder.Sent.Count);
    }

    [Fact]
    public async Task AnAddressThatIsAlreadyInvited_IsRefusedWhilePending()
    {
        var admin = AdminClientRecording(new MailRecorder());
        var email = NewAddress();
        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsJsonAsync(Invitations, new { email })).StatusCode);

        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = email.ToUpperInvariant() }), HttpStatusCode.Conflict, "invitation_already_pending", "email");
    }

    [Fact]
    public async Task WhatIsNotAnAddress_OrAnApplicationTheTenantDoesNotHave_IsRefusedNamingTheMember()
    {
        var admin = AdminClientRecording(new MailRecorder());

        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = "not an address" }), HttpStatusCode.BadRequest, "invalid_request", "email");
        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { }), HttpStatusCode.BadRequest, "invalid_request", "email");
        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = NewAddress(), client_id = "no-such-client" }), HttpStatusCode.BadRequest, "unknown_client", "client_id");
    }

    [Fact]
    public async Task AnAddressThatAlreadyHasAnAccount_IsRefused()
    {
        var admin = AdminClientRecording(new MailRecorder());
        var (_, address) = await RegisterApplicationAndPersonAsync();

        await AssertRefusedAsync(await admin.PostAsJsonAsync(Invitations, new { email = address }), HttpStatusCode.Conflict, "user_already_member", "email");
    }

    [Fact]
    public async Task AnInvitation_ForAnApplication_NamesIt()
    {
        var admin = AdminClientRecording(new MailRecorder());
        var app = (await RegisterClientAsync(admin, PublicClientBody("the app"))).GetProperty("client");
        var created = await admin.PostAsJsonAsync(Invitations, new { email = NewAddress(), client_id = app.GetProperty("client_id").GetString() });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await BodyOfAsync(created)).GetProperty("invitation").GetProperty("id").GetString()!;

        var read = (await BodyOfAsync(await admin.GetAsync(InvitationAt(id)))).GetProperty("invitation");

        Assert.Equal(app.GetProperty("client_id").GetString(), read.GetProperty("client").GetProperty("client_id").GetString());
        Assert.Equal("the app", read.GetProperty("client").GetProperty("name").GetString());
    }

    [Fact]
    public async Task APageOfInvitations_IsNewestFirst_AndCanBeFilteredByStatus()
    {
        var admin = AdminClientRecording(new MailRecorder());
        var first = await CreateInvitationAsync(admin);
        await Task.Delay(20);
        var second = await CreateInvitationAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync(InvitationAt(first))).StatusCode);

        var all = await BodyOfAsync(await admin.GetAsync(new Uri("/api/v1/invitations?limit=500", UriKind.Relative)));
        Assert.Equal(100, all.GetProperty("limit").GetInt32());
        var ids = all.GetProperty("invitations").EnumerateArray().Select(i => i.GetProperty("id").GetString()).ToList();
        Assert.True(ids.IndexOf(second) < ids.IndexOf(first), "the newer invitation comes first");

        var pending = await BodyOfAsync(await admin.GetAsync(new Uri("/api/v1/invitations?status=pending&limit=100", UriKind.Relative)));
        var pendingIds = pending.GetProperty("invitations").EnumerateArray().Select(i => i.GetProperty("id").GetString()).ToList();
        Assert.Contains(second, pendingIds);
        Assert.DoesNotContain(first, pendingIds);
        Assert.All(pending.GetProperty("invitations").EnumerateArray(), i => Assert.Equal("pending", i.GetProperty("status").GetString()));

        var one = await BodyOfAsync(await admin.GetAsync(new Uri("/api/v1/invitations?limit=1", UriKind.Relative)));
        Assert.Single(one.GetProperty("invitations").EnumerateArray());
        await AssertRefusedAsync(await admin.GetAsync(new Uri("/api/v1/invitations?status=bogus", UriKind.Relative)), HttpStatusCode.BadRequest, "invalid_request", "status");
    }

    [Fact]
    public async Task APendingInvitation_IsResentWithANewLink_AndRevokedOnce()
    {
        var recorder = new MailRecorder();
        var admin = AdminClientRecording(recorder);
        var id = await CreateInvitationAsync(admin);
        var firstLink = TokenIn(recorder.Sent.Single().Message);

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync(InvitationAt(id, "/resend"), null)).StatusCode);
        Assert.Equal(2, recorder.Sent.Count);
        Assert.NotEqual(firstLink, TokenIn(recorder.Sent.Last().Message));

        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync(InvitationAt(id))).StatusCode);
        await AssertRefusedAsync(await admin.DeleteAsync(InvitationAt(id)), HttpStatusCode.Conflict, "invitation_not_pending");
        await AssertRefusedAsync(await admin.PostAsync(InvitationAt(id, "/resend"), null), HttpStatusCode.Conflict, "invitation_not_pending");
        Assert.Equal("revoked", (await BodyOfAsync(await admin.GetAsync(InvitationAt(id)))).GetProperty("invitation").GetProperty("status").GetString());
    }

    [Fact]
    public async Task AnInvitationThatIsPendingPastItsExpiry_ReadsAsExpired_AndCannotBeResent()
    {
        var admin = AdminClientRecording(new MailRecorder());
        var id = await CreateInvitationAsync(admin);
        using (var scope = server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
            var invitation = await db.Invitations.FindAsync(Guid.Parse(id));
            invitation!.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        Assert.Equal("expired", (await BodyOfAsync(await admin.GetAsync(InvitationAt(id)))).GetProperty("invitation").GetProperty("status").GetString());
        await AssertRefusedAsync(await admin.PostAsync(InvitationAt(id, "/resend"), null), HttpStatusCode.Conflict, "invitation_not_pending");
    }

    [Fact]
    public async Task AnInvitationThatDoesNotExist_IsNotFound()
    {
        var admin = AdminClientRecording(new MailRecorder());

        await AssertRefusedAsync(await admin.GetAsync(InvitationAt(Guid.NewGuid().ToString())), HttpStatusCode.NotFound, "not_found");
        await AssertRefusedAsync(await admin.GetAsync(InvitationAt("not-an-id")), HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task WhenTheMailCannotBeSent_TheInvitationStays_AndTheAnswerSaysSo()
    {
        var recorder = new MailRecorder { Fails = true };
        var admin = AdminClientRecording(recorder);

        var response = await admin.PostAsJsonAsync(Invitations, new { email = NewAddress() });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Contains("could not be sent", (await BodyOfAsync(response)).GetProperty("message").GetString(), StringComparison.Ordinal);
        Assert.Empty(recorder.Sent);
    }

    private static async Task<string> CreateInvitationAsync(HttpClient admin)
    {
        var response = await admin.PostAsJsonAsync(Invitations, new { email = NewAddress() });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await BodyOfAsync(response)).GetProperty("invitation").GetProperty("id").GetString()!;
    }
}
