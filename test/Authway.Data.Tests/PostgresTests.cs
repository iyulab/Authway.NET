using Authway.Data;
using Authway.Data.Postgres;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;

namespace Authway.Data.Tests;

public sealed class PostgresFixture : IAsyncLifetime, IDatabaseFixture
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();

    public Task InitializeAsync() => _container.StartAsync();

    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    public DbContextOptions<AuthwayDbContext> Options()
    {
        var options = new DbContextOptionsBuilder<AuthwayDbContext>();
        options.UseAuthwayPostgres(_container.GetConnectionString());
        return options.Options;
    }
}

public sealed class PostgresTests(PostgresFixture fixture) : DatabaseTests(fixture), IClassFixture<PostgresFixture>;
