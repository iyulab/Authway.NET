using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Authway.Data;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Server.Tests;

/// <summary>What was done, and by whom, is written down; an administrator reads it and removes what is past its retention.</summary>
public abstract partial class ServerTests
{
    private static Uri AuditAt(string rest) => new($"/api/v1/audit/{rest}", UriKind.Relative);

    private static async Task<List<JsonElement>> AuditEntriesAsync(HttpClient admin, string query)
    {
        var response = await admin.GetAsync(AuditAt("logs?" + query));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return [.. (await BodyOfAsync(response)).GetProperty("logs").EnumerateArray()];
    }

    [Fact]
    public async Task AnAdminChange_IsWrittenDown_WithWhoDidItAndFromWhere()
    {
        var admin = AdminClient(AdminKey);
        admin.DefaultRequestHeaders.UserAgent.ParseAdd("audit-test/1.0");
        var created = await RegisterClientAsync(admin, PublicClientBody());
        var id = created.GetProperty("client").GetProperty("id").GetString()!;

        var entry = Assert.Single(await AuditEntriesAsync(admin, $"action=client.created&resource_id={id}"));

        Assert.Equal("api_key", entry.GetProperty("actor_type").GetString());
        Assert.Equal(JsonValueKind.Null, entry.GetProperty("actor_id").ValueKind);
        Assert.Equal("client", entry.GetProperty("resource_type").GetString());
        Assert.Equal("info", entry.GetProperty("severity").GetString());
        Assert.True(entry.GetProperty("success").GetBoolean());
        Assert.Equal("audit-test/1.0", entry.GetProperty("user_agent").GetString());
        Assert.Equal(TenantId, entry.GetProperty("tenant_id").GetString());

        // One entry by its id, and removing the client is written down too.
        var one = await BodyOfAsync(await admin.GetAsync(AuditAt("logs/" + entry.GetProperty("id").GetString())));
        Assert.Equal(id, one.GetProperty("log").GetProperty("resource_id").GetString());
        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync(ClientAt(id))).StatusCode);
        Assert.Single(await AuditEntriesAsync(admin, $"action=client.deleted&resource_id={id}"));
    }

    [Fact]
    public async Task ASignInFlow_SubmittedAgain_IsTheSameSignIn_AndIsWrittenDownOnce()
    {
        // The screen stays up while the browser follows the redirect, so the same flow is answered twice.
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var (_, otherAddress) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var path = new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative);

        var first = await browser.PostAsJsonAsync(path, new { email = address, password = Password });
        var again = await browser.PostAsJsonAsync(path, new { email = address, password = Password });
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(await first.Content.ReadAsStringAsync(), await again.Content.ReadAsStringAsync());

        // Asking again proves who you are again, and the flow belongs to the person it signed in.
        var wrong = await browser.PostAsJsonAsync(path, new { email = address, password = "not-the-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var someoneElse = await browser.PostAsJsonAsync(path, new { email = otherAddress, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, someoneElse.StatusCode);
        var anotherPassword = await browser.PostAsJsonAsync(path, new { email = otherAddress, password = "not-the-password" });
        Assert.Equal(await someoneElse.Content.ReadAsStringAsync(), await anotherPassword.Content.ReadAsStringAsync());

        var userId = Assert.Single(await AuditEntriesAsync(admin, "action=user.login_failed&success=false&limit=1000"), e => e.GetProperty("actor_email").GetString() == address).GetProperty("actor_id").GetString()!;
        Assert.Single(await AuditEntriesAsync(admin, $"action=user.login&actor_id={userId}"));
    }

    [Fact]
    public async Task ASignInFlow_SubmittedAtOnce_IsOneSignIn()
    {
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var path = new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative);

        var answers = await Task.WhenAll(Enumerable.Range(0, 6).Select(async _ =>
        {
            var response = await browser.PostAsJsonAsync(path, new { email = address, password = Password });
            return (response.StatusCode, Body: await response.Content.ReadAsStringAsync());
        }));

        Assert.All(answers, a => Assert.Equal(HttpStatusCode.OK, a.StatusCode));
        Assert.Single(answers.Select(a => a.Body).Distinct());
        Assert.Single(await AuditEntriesAsync(admin, "action=user.login&limit=1000"), e => e.GetProperty("actor_email").GetString() == address);
    }

    [Fact]
    public async Task ASignIn_IsWrittenDown_WhetherItWorkedOrNot()
    {
        var admin = AdminClient(AdminKey);
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);

        await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = "not-the-password" });
        await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });

        var refused = Assert.Single(await AuditEntriesAsync(admin, $"action=user.login_failed&success=false&severity=warning&limit=1000"), e => e.GetProperty("actor_email").GetString() == address);
        Assert.Equal("wrong password", refused.GetProperty("error_msg").GetString());
        var userId = refused.GetProperty("actor_id").GetString()!;

        var worked = Assert.Single(await AuditEntriesAsync(admin, $"action=user.login&actor_id={userId}"));
        Assert.Equal(userId, worked.GetProperty("resource_id").GetString());
        Assert.True(worked.GetProperty("success").GetBoolean());

        // What the person did is theirs to read as activity; the refusal is a security event.
        var activity = await BodyOfAsync(await admin.GetAsync(AuditAt($"users/{userId}/activity")));
        Assert.True(activity.GetProperty("logs").GetArrayLength() >= 2);
        var security = await BodyOfAsync(await admin.GetAsync(AuditAt("security")));
        Assert.Contains(security.GetProperty("logs").EnumerateArray(), e => e.GetProperty("actor_email").GetString() == address);
        var summary = (await BodyOfAsync(await admin.GetAsync(AuditAt("summary")))).GetProperty("summary");
        Assert.True(summary.GetProperty("failed_operations").GetInt32() >= 1);
        Assert.True(summary.GetProperty("security_events").GetInt32() >= 1);
        Assert.True(summary.GetProperty("total_24h").GetInt32() >= summary.GetProperty("failed_operations").GetInt32());
    }

    [Fact]
    public async Task ARefusedSignIn_IsWrittenDown_EvenWhenWhatWasTypedIsFarTooLongToBeAnAddress()
    {
        var admin = AdminClient(AdminKey);
        var (application, _) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);
        var typed = new string('a', 5000) + "@example.test";

        var refused = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = typed, password = "not-the-password" });

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var entries = await AuditEntriesAsync(admin, "action=user.login_failed&limit=1000");
        Assert.Contains(entries, e => e.GetProperty("actor_email").GetString() is { Length: 320 } email && email.StartsWith("aaaa", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("action=user.exploded", "action")]
    [InlineData("severity=loud", "severity")]
    [InlineData("success=maybe", "success")]
    [InlineData("actor_id=not-an-id", "actor_id")]
    [InlineData("start_time=yesterday", "start_time")]
    [InlineData("end_time=2026-11-04", "end_time")]
    [InlineData("limit=0", "limit")]
    [InlineData("limit=1001", "limit")]
    [InlineData("offset=-1", "offset")]
    public async Task AFilterThatIsNotWellFormed_IsRefused_NotIgnored(string query, string field)
    {
        var admin = AdminClient(AdminKey);

        await AssertRefusedAsync(await admin.GetAsync(AuditAt("logs?" + query)), HttpStatusCode.BadRequest, "invalid_request", field);
    }

    [Fact]
    public async Task TheLog_NarrowsByWhen_AndPagesNewestFirst()
    {
        var admin = AdminClient(AdminKey);
        var first = await RegisterClientAsync(admin, PublicClientBody());
        var second = await RegisterClientAsync(admin, PublicClientBody());
        var ids = new[] { first, second }.Select(c => c.GetProperty("client").GetProperty("id").GetString()!).ToList();

        var all = await AuditEntriesAsync(admin, "action=client.created&limit=1000");
        var positions = ids.Select(id => all.FindIndex(e => e.GetProperty("resource_id").GetString() == id)).ToList();
        Assert.All(positions, p => Assert.True(p >= 0));
        Assert.True(positions[1] < positions[0], "the later change is listed first");

        var at = DateTimeOffset.Parse(all[positions[0]].GetProperty("created_at").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
        string Iso(DateTimeOffset t) => Uri.EscapeDataString(t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Empty(await AuditEntriesAsync(admin, $"resource_id={ids[0]}&end_time={Iso(at.AddMinutes(-1))}"));
        Assert.Empty(await AuditEntriesAsync(admin, $"resource_id={ids[0]}&start_time={Iso(at.AddMinutes(1))}"));
        Assert.Single(await AuditEntriesAsync(admin, $"resource_id={ids[0]}&start_time={Iso(at.AddMinutes(-1))}&end_time={Iso(at.AddMinutes(1))}"));

        var page = await BodyOfAsync(await admin.GetAsync(AuditAt("logs?limit=1&offset=1")));
        Assert.Equal(1, page.GetProperty("logs").GetArrayLength());
        Assert.Equal(1, page.GetProperty("limit").GetInt32());
        Assert.Equal(1, page.GetProperty("offset").GetInt32());
        Assert.True(page.GetProperty("total").GetInt32() >= 2);
    }

    [Fact]
    public async Task AnEntryThatDoesNotExist_IsNotFound_AndTheActionsListOnlyWhatIsRecorded()
    {
        var admin = AdminClient(AdminKey);

        await AssertRefusedAsync(await admin.GetAsync(AuditAt("logs/00000000-0000-0000-0000-000000000001")), HttpStatusCode.NotFound, "not_found");
        await AssertRefusedAsync(await admin.GetAsync(AuditAt("logs/nope")), HttpStatusCode.BadRequest, "invalid_request");
        await AssertRefusedAsync(await admin.GetAsync(AuditAt("security?hours=169")), HttpStatusCode.BadRequest, "invalid_request");

        var actions = (await BodyOfAsync(await admin.GetAsync(AuditAt("actions")))).GetProperty("actions").EnumerateArray().Select(a => a.GetProperty("action").GetString()).ToList();
        Assert.Contains("user.login_failed", actions);
        Assert.Contains("client.created", actions);
        Assert.DoesNotContain("webhook.created", actions);
        Assert.DoesNotContain("tenant.created", actions);
        Assert.Empty((await BodyOfAsync(await admin.GetAsync(AuditAt("users/00000000-0000-0000-0000-000000000001/activity?limit=5")))).GetProperty("logs").EnumerateArray());
    }

    [Fact]
    public async Task APurge_RefusesWhatIsShorterThanTheLeastRetention_AndRemovesOnlyWhatIsPast()
    {
        var admin = AdminClient(AdminKey);
        await AssertRefusedAsync(await admin.DeleteAsync(AuditAt("logs/purge?retention_days=7")), HttpStatusCode.BadRequest, "invalid_request", "retention_days");

        var old = Guid.NewGuid();
        var recent = Guid.NewGuid();
        using (var scope = server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthwayDbContext>();
            db.AuditLogs.Add(new AuditLog { Id = old, TenantId = Guid.Parse(TenantId), ActorType = "system", Action = "client.created", Severity = "info", CreatedAt = DateTimeOffset.UtcNow.AddDays(-400) });
            db.AuditLogs.Add(new AuditLog { Id = recent, TenantId = Guid.Parse(TenantId), ActorType = "system", Action = "client.created", Severity = "info", CreatedAt = DateTimeOffset.UtcNow.AddDays(-10) });
            await db.SaveChangesAsync();
        }

        var purged = await BodyOfAsync(await admin.DeleteAsync(AuditAt("logs/purge")));

        Assert.Equal(365, purged.GetProperty("retention_days").GetInt32());
        // Not a count of what this call removed: the retention job that runs beside the server may have removed
        // the old row first, and the row being gone is what the purge promises.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync(AuditAt($"logs/{old}"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync(AuditAt($"logs/{recent}"))).StatusCode);

        var shorter = await BodyOfAsync(await admin.DeleteAsync(AuditAt("logs/purge?retention_days=30")));
        Assert.Equal(30, shorter.GetProperty("retention_days").GetInt32());
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync(AuditAt($"logs/{recent}"))).StatusCode);
    }

    [Fact]
    public async Task TheLog_IsReadOnlyWithTheAdministrationKey()
    {
        var anonymous = AdminClient(null);

        await AssertRefusedAsync(await anonymous.GetAsync(AuditAt("logs")), HttpStatusCode.Unauthorized, "unauthorized");
        await AssertRefusedAsync(await anonymous.DeleteAsync(AuditAt("logs/purge")), HttpStatusCode.Unauthorized, "unauthorized");
    }
}
