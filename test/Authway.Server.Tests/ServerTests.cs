using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

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

    [Fact]
    public async Task ClientCredentials_IssueASignedJwtForTheClient()
    {
        var (clientId, secret) = await RegisterServiceAsync(Permissions.Scopes.Profile);

        var response = await RequestTokenAsync(clientId, secret, scope: "profile");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Bearer", body.RootElement.GetProperty("token_type").GetString());

        // A resource server reads the token with the published keys: it is a signed JWT, not an opaque handle.
        var token = body.RootElement.GetProperty("access_token").GetString()!;
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        using var claims = JsonDocument.Parse(Base64UrlEncoder.Decode(parts[1]));
        Assert.Equal(clientId, claims.RootElement.GetProperty("sub").GetString());
        Assert.False(string.IsNullOrEmpty(claims.RootElement.GetProperty("iss").GetString()));
        Assert.True(claims.RootElement.GetProperty("exp").GetInt64() > DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        // The scope it was granted is in the token (a string or a list, depending on the library's version).
        var granted = claims.RootElement.GetProperty("scope");
        var scopes = granted.ValueKind == JsonValueKind.Array
            ? granted.EnumerateArray().Select(s => s.GetString()).ToList()
            : granted.GetString()!.Split(' ').Cast<string?>().ToList();
        Assert.Contains("profile", scopes);
    }

    [Fact]
    public async Task ClientCredentials_WithAWrongSecret_AreRefused()
    {
        var (clientId, _) = await RegisterServiceAsync();

        var response = await RequestTokenAsync(clientId, "not-the-secret");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_client", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ClientCredentials_AreRefusedToAClientNotRegisteredForThem()
    {
        var (clientId, secret) = await RegisterServiceAsync(grant: Permissions.GrantTypes.AuthorizationCode);

        var response = await RequestTokenAsync(clientId, secret);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("unauthorized_client", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AGrantTheServerDoesNotKnow_IsRefused()
    {
        var (clientId, secret) = await RegisterServiceAsync();

        var response = await server.Client.PostAsync(new Uri("/connect/token", UriKind.Relative), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["username"] = "someone@example.test",
            ["password"] = "correct-Horse-9",
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("unsupported_grant_type", body.RootElement.GetProperty("error").GetString());
    }

    /// <summary>Registers a confidential application the way an administrator would, and returns its credentials.</summary>
    private async Task<(string ClientId, string Secret)> RegisterServiceAsync(string? scope = null, string grant = Permissions.GrantTypes.ClientCredentials)
    {
        using var scopeOfServices = server.Services.CreateScope();
        var applications = scopeOfServices.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var clientId = $"service-{Guid.NewGuid():N}";
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = "Service under test",
            Permissions = { Permissions.Endpoints.Token, grant },
        };
        if (scope is not null)
        {
            descriptor.Permissions.Add(scope);
        }

        await applications.CreateAsync(descriptor);
        return (clientId, secret);
    }

    private Task<HttpResponseMessage> RequestTokenAsync(string clientId, string secret, string? scope = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        return server.Client.PostAsync(new Uri("/connect/token", UriKind.Relative), new FormUrlEncodedContent(form));
    }
}
