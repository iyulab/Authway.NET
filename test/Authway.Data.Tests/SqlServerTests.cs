using Authway.Data;
using Authway.Data.SqlServer;
using Microsoft.EntityFrameworkCore;
using Testcontainers.MsSql;

namespace Authway.Data.Tests;

public sealed class SqlServerFixture : IAsyncLifetime, IDatabaseFixture
{
    private readonly MsSqlContainer _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest").Build();

    public Task InitializeAsync() => _container.StartAsync();

    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    public DbContextOptions<AuthwayDbContext> Options() =>
        new DbContextOptionsBuilder<AuthwayDbContext>().UseAuthwaySqlServer(_container.GetConnectionString()).Options;
}

public sealed class SqlServerTests(SqlServerFixture fixture) : DatabaseTests(fixture), IClassFixture<SqlServerFixture>;
