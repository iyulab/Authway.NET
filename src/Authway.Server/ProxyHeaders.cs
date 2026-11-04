using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Authway.Server;

/// <summary>
/// The address the server tells people to use — the issuer in its discovery document, the pages it sends a
/// browser to, the https it insists on — is read from the request. Behind a reverse proxy that ends TLS (IIS,
/// a load balancer, a container's ingress) the request the server sees is plain http for the proxy's own
/// address, so those answers would name the wrong address, and the server would refuse to answer at all
/// outside development.
/// <para>
/// A proxy says what the person's request looked like in <c>X-Forwarded-Proto</c>, <c>-Host</c> and <c>-For</c>.
/// Anyone can send those headers, though, so they are read only from the proxies the installation names, and
/// not at all unless it turns this on:
/// </para>
/// <list type="bullet">
/// <item><c>Authway:Proxy:ForwardedHeaders</c> — <c>true</c> to read them (default <c>false</c>).</item>
/// <item><c>Authway:Proxy:KnownProxies</c> — the addresses of the proxies to believe.</item>
/// <item><c>Authway:Proxy:KnownNetworks</c> — networks of proxies to believe, as <c>10.0.0.0/8</c>.</item>
/// <item>With neither list, only a proxy on the same machine (loopback) is believed.</item>
/// </list>
/// </summary>
internal static class ProxyHeaders
{
    private const string Section = "Authway:Proxy";

    public static bool Enabled(IConfiguration configuration) => configuration.GetValue($"{Section}:ForwardedHeaders", false);

    /// <summary>
    /// The options are read from the configuration when they are first needed, not when the services are
    /// registered, so the configuration the host ends up with is the one that counts.
    /// </summary>
    public static void Add(IServiceCollection services) =>
        services.AddOptions<ForwardedHeadersOptions>().Configure<IConfiguration>((options, configuration) =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (var address in configuration.GetSection($"{Section}:KnownProxies").Get<string[]>() ?? [])
            {
                options.KnownProxies.Add(IPAddress.Parse(address));
            }

            foreach (var network in configuration.GetSection($"{Section}:KnownNetworks").Get<string[]>() ?? [])
            {
                options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
            }

            if (options.KnownProxies.Count == 0 && options.KnownIPNetworks.Count == 0)
            {
                options.KnownProxies.Add(IPAddress.Loopback);
                options.KnownProxies.Add(IPAddress.IPv6Loopback);
            }
        });

    /// <summary>First in the pipeline: everything after it sees the address the person used.</summary>
    public static void Use(WebApplication app)
    {
        if (Enabled(app.Configuration))
        {
            app.UseForwardedHeaders();
        }
    }
}
