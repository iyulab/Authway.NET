using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authway.Server.Tests;

/// <summary>Behind a proxy that ends TLS the server names the address the person used — from the proxies it is told to believe, and only those.</summary>
public abstract partial class ServerTests
{
    private static readonly Uri Discovery = new("/.well-known/openid-configuration", UriKind.Relative);

    /// <summary>Makes every request look as if it came from this address, as a proxy's would.</summary>
    private sealed class ComesFrom(string address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, pipeline) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(address);
                return pipeline();
            });
            next(app);
        };
    }

    private async Task<string?> IssuerSeenThroughAsync(IReadOnlyDictionary<string, string?> configuration, string proxyAddress)
    {
        using var client = server.CreateClientWith(configuration, services => services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter>(new ComesFrom(proxyAddress))));
        using var request = new HttpRequestMessage(HttpMethod.Get, Discovery);
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Forwarded-Host", "auth.example.test");
        var body = await BodyOfAsync(await client.SendAsync(request));
        return body.GetProperty("issuer").GetString();
    }

    [Fact]
    public async Task ForwardedHeaders_AreIgnored_UnlessTheInstallationTurnsThemOn()
    {
        var issuer = await IssuerSeenThroughAsync(new Dictionary<string, string?>(), "127.0.0.1");

        Assert.DoesNotContain("auth.example.test", issuer);
    }

    [Fact]
    public async Task ForwardedHeaders_NameTheAddressOfThePerson_WhenTheyComeFromAProxyTheInstallationNames()
    {
        var configuration = new Dictionary<string, string?>
        {
            ["Authway:Proxy:ForwardedHeaders"] = "true",
            ["Authway:Proxy:KnownProxies:0"] = "192.0.2.10",
        };

        Assert.Equal("https://auth.example.test/", await IssuerSeenThroughAsync(configuration, "192.0.2.10"));
    }

    [Fact]
    public async Task ForwardedHeaders_AreNotBelieved_FromAnAddressTheInstallationDidNotName()
    {
        var configuration = new Dictionary<string, string?>
        {
            ["Authway:Proxy:ForwardedHeaders"] = "true",
            ["Authway:Proxy:KnownProxies:0"] = "192.0.2.10",
        };

        Assert.DoesNotContain("auth.example.test", await IssuerSeenThroughAsync(configuration, "203.0.113.7"));
    }

    [Fact]
    public async Task ForwardedHeaders_AreBelievedFromANamedNetwork_AndFromTheSameMachineWhenNoneIsNamed()
    {
        var network = new Dictionary<string, string?>
        {
            ["Authway:Proxy:ForwardedHeaders"] = "true",
            ["Authway:Proxy:KnownNetworks:0"] = "10.0.0.0/8",
        };
        Assert.Equal("https://auth.example.test/", await IssuerSeenThroughAsync(network, "10.4.5.6"));

        var none = new Dictionary<string, string?> { ["Authway:Proxy:ForwardedHeaders"] = "true" };
        Assert.Equal("https://auth.example.test/", await IssuerSeenThroughAsync(none, "127.0.0.1"));
        Assert.DoesNotContain("auth.example.test", await IssuerSeenThroughAsync(none, "10.4.5.6"));
    }
}
