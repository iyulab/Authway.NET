using Authway.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.MsSql;
using Testcontainers.PostgreSql;

namespace Authway.Server.Tests;

/// <summary>A real database of one provider, and the server running against it.</summary>
public interface IServerFixture
{
    HttpClient Client { get; }

    /// <summary>A client of its own: with a browser's cookies, and following redirects or not as the test needs.</summary>
    HttpClient CreateClient(bool followRedirects);

    /// <summary>A client of a server of its own on the same database, run with this configuration on top.</summary>
    HttpClient CreateClientWith(IReadOnlyDictionary<string, string?> configuration);

    IServiceProvider Services { get; }
}

public abstract class ServerFixture : IAsyncLifetime, IServerFixture
{
    private WebApplicationFactory<Program>? _factory;

    /// <summary>A stand-in for the build of the sign-in screens, which the server serves.</summary>
    public string UiDirectory { get; } = Path.Combine(Path.GetTempPath(), $"authway-ui-{Guid.NewGuid():N}");

    protected abstract DatabaseProvider Provider { get; }

    protected abstract Task StartDatabaseAsync();

    protected abstract Task StopDatabaseAsync();

    protected abstract string ConnectionString { get; }

    public HttpClient Client => _factory!.CreateClient();

    public HttpClient CreateClient(bool followRedirects) =>
        _factory!.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = followRedirects, HandleCookies = true });

    public HttpClient CreateClientWith(IReadOnlyDictionary<string, string?> configuration) =>
        _factory!
            .WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(configuration)))
            .CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    public IServiceProvider Services => _factory!.Services;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Path.Combine(UiDirectory, "assets"));
        await File.WriteAllTextAsync(Path.Combine(UiDirectory, "index.html"), "<!doctype html><title>sign-in screens</title>");
        await File.WriteAllTextAsync(Path.Combine(UiDirectory, "assets", "app.js"), "console.log('screen');");
        await StartDatabaseAsync();
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authway:Database:Provider"] = Provider.ToString(),
                ["ConnectionStrings:Authway"] = ConnectionString,
                ["Authway:Ui:Directory"] = UiDirectory,
            }));
        });
        // The server creates the schema it runs on when it starts.
        using var scope = _factory.Services.CreateScope();
        await Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.MigrateAsync(scope.ServiceProvider.GetRequiredService<AuthwayDbContext>().Database);
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        await StopDatabaseAsync();
        Directory.Delete(UiDirectory, recursive: true);
    }
}

public sealed class PostgresServerFixture : ServerFixture
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();

    protected override DatabaseProvider Provider => DatabaseProvider.PostgreSql;

    protected override string ConnectionString => _container.GetConnectionString();

    protected override Task StartDatabaseAsync() => _container.StartAsync();

    protected override Task StopDatabaseAsync() => _container.DisposeAsync().AsTask();
}

public sealed class SqlServerServerFixture : ServerFixture
{
    private readonly MsSqlContainer _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest").Build();

    protected override DatabaseProvider Provider => DatabaseProvider.SqlServer;

    protected override string ConnectionString => _container.GetConnectionString();

    protected override Task StartDatabaseAsync() => _container.StartAsync();

    protected override Task StopDatabaseAsync() => _container.DisposeAsync().AsTask();
}
