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

    IServiceProvider Services { get; }
}

public abstract class ServerFixture : IAsyncLifetime, IServerFixture
{
    private WebApplicationFactory<Program>? _factory;

    protected abstract DatabaseProvider Provider { get; }

    protected abstract Task StartDatabaseAsync();

    protected abstract Task StopDatabaseAsync();

    protected abstract string ConnectionString { get; }

    public HttpClient Client => _factory!.CreateClient();

    public IServiceProvider Services => _factory!.Services;

    public async Task InitializeAsync()
    {
        await StartDatabaseAsync();
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authway:Database:Provider"] = Provider.ToString(),
                ["ConnectionStrings:Authway"] = ConnectionString,
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
