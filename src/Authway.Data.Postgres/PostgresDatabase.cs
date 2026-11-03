using Authway.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Authway.Data.Postgres;

/// <summary>Configures <see cref="AuthwayDbContext"/> for PostgreSQL.</summary>
public static class PostgresDatabase
{
    public static DbContextOptionsBuilder<AuthwayDbContext> UseAuthwayPostgres(
        this DbContextOptionsBuilder<AuthwayDbContext> options, string connectionString)
    {
        options.UseNpgsql(connectionString, npgsql =>
            npgsql.MigrationsAssembly(typeof(PostgresDatabase).Assembly.GetName().Name));
        return options;
    }
}

/// <summary>What <c>dotnet ef</c> builds the context with when it adds a PostgreSQL migration.</summary>
public sealed class PostgresDesignTimeFactory : IDesignTimeDbContextFactory<AuthwayDbContext>
{
    public AuthwayDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthwayDbContext>()
            .UseAuthwayPostgres("Host=localhost;Database=authway_design;Username=design;Password=design");
        return new AuthwayDbContext(options.Options);
    }
}
