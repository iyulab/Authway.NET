using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Authway.Server.Tests;

/// <summary>Who may use the administration API: whoever holds the installation's key, and nobody when it has none.</summary>
public abstract partial class ServerTests
{
    private const string AdminKey = "a-key-for-the-tests-only";

    private HttpClient AdminClient(string? bearer)
    {
        var client = server.CreateClientWith(new Dictionary<string, string?> { ["Authway:Admin:ApiKey"] = AdminKey });
        if (bearer is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        return client;
    }

    private static async Task<string?> CodeOfAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("code").GetString();
    }

    [Fact]
    public async Task WithoutAKeyConfigured_NothingIsAdministered()
    {
        var response = await server.Client.GetAsync(new Uri("/api/v1/tenants", UriKind.Relative));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("admin_api_not_configured", await CodeOfAsync(response));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-the-key")]
    [InlineData("")]
    public async Task ACallWithoutTheKey_IsRefused_NamingTheScheme(string? bearer)
    {
        var response = await AdminClient(bearer).GetAsync(new Uri("/api/v1/tenants", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        Assert.Equal("unauthorized", await CodeOfAsync(response));
    }

    [Fact]
    public async Task ACallWithTheKey_ListsTheOneTenant()
    {
        var response = await AdminClient(AdminKey).GetAsync(new Uri("/api/v1/tenants", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var tenants = body.RootElement.EnumerateArray().ToList();
        var tenant = Assert.Single(tenants);
        Assert.Equal("default", tenant.GetProperty("slug").GetString());
        Assert.Equal("00000000-0000-0000-0000-000000000001", tenant.GetProperty("id").GetString());
        Assert.True(tenant.GetProperty("active").GetBoolean());
    }
}
