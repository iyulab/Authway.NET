using System.Net;
using System.Text.Json;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Server.Tests;

/// <summary>What the server must do on every database an installation can run on.</summary>
public abstract class ServerTests(IServerFixture server)
{
    [Fact]
    public async Task Discovery_AnnouncesTheEndpointsAndTheKeys()
    {
        var client = server.Client;

        var response = await client.GetAsync(new Uri("/.well-known/openid-configuration", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;

        foreach (var endpoint in new[] { "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "end_session_endpoint", "jwks_uri" })
        {
            Assert.True(root.TryGetProperty(endpoint, out var value) && value.GetString()?.Length > 0, $"{endpoint} is announced");
        }

        var methods = root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(m => m.GetString()).ToList();
        Assert.Contains("S256", methods);
        Assert.DoesNotContain("plain", methods);

        var keys = await client.GetAsync(new Uri(root.GetProperty("jwks_uri").GetString()!));
        Assert.Equal(HttpStatusCode.OK, keys.StatusCode);
        using var jwks = JsonDocument.Parse(await keys.Content.ReadAsStringAsync());
        Assert.NotEqual(0, jwks.RootElement.GetProperty("keys").GetArrayLength());
    }

    [Fact]
    public async Task Accounts_AreStoredByAddress_AndAnAddressIsOneAccount()
    {
        using var scope = server.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var address = $"person-{Guid.NewGuid():N}@example.test";

        var created = await users.CreateAsync(new ApplicationUser { UserName = address, Email = address, DisplayName = "Person" }, "correct-Horse-9");
        Assert.True(created.Succeeded, string.Join(", ", created.Errors.Select(e => e.Description)));

        var found = await users.FindByEmailAsync(address.ToUpperInvariant());
        Assert.NotNull(found);
        Assert.Equal("Person", found!.DisplayName);
        Assert.True(await users.CheckPasswordAsync(found, "correct-Horse-9"));

        var again = await users.CreateAsync(new ApplicationUser { UserName = address.ToUpperInvariant(), Email = address.ToUpperInvariant() }, "correct-Horse-9");
        Assert.False(again.Succeeded, "a second account for the same address was made");
    }
}
