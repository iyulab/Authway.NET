using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authway.Data;

/// <summary>
/// Everything Authway stores, in the one database the installation points at.
/// The model is provider-neutral; each provider keeps its own migrations
/// (Authway.Data.Postgres, Authway.Data.SqlServer), chosen when the context is
/// configured.
/// </summary>
public class AuthwayDbContext(DbContextOptions<AuthwayDbContext> options)
    : DbContext(options), IDataProtectionKeyContext
{
    /// <summary>The keys ASP.NET Core's data protection keeps its secrets under.</summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<DataProtectionKey>().ToTable("data_protection_keys");
    }
}
