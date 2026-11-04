using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Authway.Server.Flows;

namespace Authway.Server.Tests;

/// <summary>How much guessing a sign-in takes before it stops being answered.</summary>
public abstract partial class ServerTests
{
    [Fact]
    public async Task ASignInThatIsAnsweredWrongTooOften_Ends()
    {
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var browser = server.CreateClient(followRedirects: false);
        var flow = await StartAsync(browser, application, Pkce.New().Challenge);

        // Unknown addresses count as well as wrong passwords: the guesser is not told which he has.
        for (var attempt = 1; attempt <= IFlowStore.MaxFailures; attempt++)
        {
            var email = attempt % 2 == 0 ? address : $"nobody-{attempt}@example.test";
            var wrong = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email, password = "not-the-password" });
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // Even the right answer comes too late: whoever is guessing starts again from the application.
        var late = await browser.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });
        Assert.Equal(HttpStatusCode.Gone, late.StatusCode);
        using var body = JsonDocument.Parse(await late.Content.ReadAsStringAsync());
        Assert.Equal("flow_expired", body.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task OneAddress_MayAnswerSignInsOnlySoOften()
    {
        var limited = server.CreateClientWith(new Dictionary<string, string?> { ["Authway:Limits:SignInPerMinute"] = "3" });
        var (application, address) = await RegisterApplicationAndPersonAsync();
        var flow = await StartAsync(limited, application, Pkce.New().Challenge);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var allowed = await limited.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = "not-the-password" });
            Assert.Equal(HttpStatusCode.Unauthorized, allowed.StatusCode);
        }

        var refused = await limited.PostAsJsonAsync(new Uri($"/api/v1/login-flows/{flow}/password", UriKind.Relative), new { email = address, password = Password });

        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.Equal("application/problem+json", refused.Content.Headers.ContentType?.MediaType);
        Assert.True(refused.Headers.RetryAfter?.Delta > TimeSpan.Zero, "the answer says when to come back");
        using var body = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        Assert.Equal("too_many_requests", body.RootElement.GetProperty("code").GetString());
        Assert.Equal(429, body.RootElement.GetProperty("status").GetInt32());
        Assert.True(body.RootElement.GetProperty("retry_after").GetInt32() > 0);

        // The refused answer did not spend the flow: it is still there for whoever may come back.
        Assert.Equal(HttpStatusCode.OK, (await limited.GetAsync(new Uri($"/api/v1/login-flows/{flow}", UriKind.Relative))).StatusCode);
    }
}
