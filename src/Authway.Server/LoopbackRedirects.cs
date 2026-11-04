using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;

namespace Authway.Server;

/// <summary>
/// RFC 8252 §7.3: a native application that listens on a loopback address cannot know its port before it is
/// started, so a redirect address registered as <c>http://127.0.0.1/callback</c> (or <c>http://[::1]/callback</c>)
/// is also the address at any port. Only that: the scheme, the address and the path stay exact, and a name such as
/// <c>localhost</c>, which a hosts file can point anywhere, is not a loopback address here.
/// </summary>
internal sealed class LoopbackRedirectApplicationManager<TApplication>(
    IOpenIddictApplicationCache<TApplication> cache,
    ILogger<OpenIddictApplicationManager<TApplication>> logger,
    IOptionsMonitor<OpenIddictCoreOptions> options,
    IOpenIddictApplicationStore<TApplication> store)
    : OpenIddictApplicationManager<TApplication>(cache, logger, options, store)
    where TApplication : class
{
    public override async ValueTask<bool> ValidateRedirectUriAsync(TApplication application, string uri, CancellationToken cancellationToken = default)
    {
        if (await base.ValidateRedirectUriAsync(application, uri, cancellationToken))
        {
            return true;
        }

        if (!TryLoopback(uri, out var requested))
        {
            return false;
        }

        foreach (var registered in await GetRedirectUrisAsync(application, cancellationToken))
        {
            if (TryLoopback(registered, out var known)
                && Equals(known.Address, requested.Address)
                && string.Equals(known.PathAndQuery, requested.PathAndQuery, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryLoopback(string value, out (IPAddress Address, string PathAndQuery) parts)
    {
        parts = default;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !IPAddress.TryParse(uri.IdnHost, out var address)
            || !IPAddress.IsLoopback(address))
        {
            return false;
        }

        parts = (address, uri.PathAndQuery);
        return true;
    }
}
