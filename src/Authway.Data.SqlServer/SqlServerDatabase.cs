using Authway.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Authway.Data.SqlServer;

/// <summary>Configures <see cref="AuthwayDbContext"/> for SQL Server.</summary>
public static class SqlServerDatabase
{
    public static DbContextOptionsBuilder<AuthwayDbContext> UseAuthwaySqlServer(
        this DbContextOptionsBuilder<AuthwayDbContext> options, string connectionString)
    {
        options.UseSqlServer(connectionString, sql =>
            sql.MigrationsAssembly(typeof(SqlServerDatabase).Assembly.GetName().Name));
        return options;
    }
}

/// <summary>What <c>dotnet ef</c> builds the context with when it adds a SQL Server migration.</summary>
public sealed class SqlServerDesignTimeFactory : IDesignTimeDbContextFactory<AuthwayDbContext>
{
    public AuthwayDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthwayDbContext>()
            .UseAuthwaySqlServer("Server=localhost;Database=authway_design;User Id=design;Password=design;TrustServerCertificate=true");
        return new AuthwayDbContext(options.Options);
    }
}
