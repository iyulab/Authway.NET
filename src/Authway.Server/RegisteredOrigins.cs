using OpenIddict.Abstractions;

namespace Authway.Server;

/// <summary>
/// The origins the clients registered (<c>allowed_origins</c>), kept in memory. A page asks whether its origin is
/// one of them before it has shown anyone's token, so the question is asked by anybody, as often as they like, and
/// must not cost a read of every client each time. The set is read again when a client is created, changed or deleted
/// and, in case another instance did it, after <see cref="Lifetime"/>.
/// </summary>
internal sealed class RegisteredOrigins(IServiceScopeFactory scopes, TimeProvider time) : IDisposable
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);

    private readonly SemaphoreSlim _reading = new(1, 1);
    private volatile Snapshot? _snapshot;

    public async ValueTask<bool> ContainsAsync(string origin)
    {
        var snapshot = _snapshot;
        if (snapshot is null || snapshot.ReadAt + Lifetime <= time.GetUtcNow())
        {
            snapshot = await ReadAsync();
        }

        return snapshot.Origins.Contains(origin);
    }

    /// <summary>The clients changed: the next question reads them again.</summary>
    public void Invalidate() => _snapshot = null;

    private async Task<Snapshot> ReadAsync()
    {
        await _reading.WaitAsync();
        try
        {
            // Another caller may have read while this one waited.
            if (_snapshot is { } fresh && fresh.ReadAt + Lifetime > time.GetUtcNow())
            {
                return fresh;
            }

            var readAt = time.GetUtcNow();
            var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var scope = scopes.CreateScope();
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await foreach (var application in applications.ListAsync())
            {
                var properties = await applications.GetPropertiesAsync(application);
                if (properties.TryGetValue("allowed_origins", out var listed) && listed.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var origin in listed.EnumerateArray().Where(o => o.ValueKind == System.Text.Json.JsonValueKind.String))
                    {
                        origins.Add(origin.GetString()!);
                    }
                }
            }

            var snapshot = new Snapshot(origins, readAt);
            _snapshot = snapshot;
            return snapshot;
        }
        finally
        {
            _reading.Release();
        }
    }

    public void Dispose() => _reading.Dispose();

    private sealed record Snapshot(HashSet<string> Origins, DateTimeOffset ReadAt);
}
