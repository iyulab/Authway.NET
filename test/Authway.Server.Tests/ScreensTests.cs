using System.Net;
using System.Text.Json;

namespace Authway.Server.Tests;

/// <summary>What the screens and their callers find on the address the server is on.</summary>
public abstract partial class ServerTests
{
    [Fact]
    public async Task Capabilities_SayWhatThisInstallationOffers_InTheShapeTheContractGives()
    {
        var response = await server.Client.GetAsync(new Uri("/api/v1/capabilities", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var capabilities = body.RootElement;
        foreach (var required in new[]
        {
            "multi_tenant", "providers", "magic_link", "mfa", "signup_modes", "account_deletion", "custom_claims",
            "backchannel_logout", "token_introspection", "device_authorization", "terms_acceptance", "token_exchange",
            "approval_requests", "ciba",
        })
        {
            Assert.True(capabilities.TryGetProperty(required, out _), $"{required} is answered");
        }

        Assert.False(capabilities.GetProperty("multi_tenant").GetBoolean());
        Assert.False(capabilities.GetProperty("magic_link").GetBoolean());
        Assert.Equal(0, capabilities.GetProperty("providers").GetArrayLength());
        Assert.Equal("invite_only", capabilities.GetProperty("signup_modes").EnumerateArray().Select(m => m.GetString()).Single());
    }

    [Fact]
    public async Task AScreenIsAPageOfTheApplication_AtItsOwnAddress()
    {
        var screen = await server.Client.GetAsync(new Uri("/login?flow=anything", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, screen.StatusCode);
        Assert.Equal("text/html", screen.Content.Headers.ContentType?.MediaType);
        Assert.Contains("sign-in screens", await screen.Content.ReadAsStringAsync());

        var asset = await server.Client.GetAsync(new Uri("/assets/app.js", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
        Assert.Contains("screen", await asset.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task TheScreensAreToldWhereTheApiIs_AndNotToRemember()
    {
        var response = await server.Client.GetAsync(new Uri("/config.js", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("javascript", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("""window.__AUTHWAY_CONFIG__ = {"apiUrl":""};""", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/api/v1/nothing-here")]
    [InlineData("/connect/nothing-here")]
    [InlineData("/.well-known/nothing-here")]
    public async Task WhatTheServerAnswersItself_IsNotFoundRatherThanAScreen(string path)
    {
        var response = await server.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("sign-in screens", await response.Content.ReadAsStringAsync());
    }
}
