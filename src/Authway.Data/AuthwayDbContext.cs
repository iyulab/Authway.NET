using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authway.Data;

/// <summary>
/// Everything Authway stores, in the one database the installation points at:
/// the accounts (ASP.NET Core Identity), what the authorization server keeps
/// (OpenIddict's applications, authorizations, scopes and tokens) and the data
/// protection key ring. The model is provider-neutral; each provider keeps its
/// own migrations (Authway.Data.Postgres, Authway.Data.SqlServer), chosen when
/// the context is configured.
/// </summary>
public class AuthwayDbContext(DbContextOptions<AuthwayDbContext> options)
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options), IDataProtectionKeyContext
{
    /// <summary>The keys ASP.NET Core's data protection keeps its secrets under.</summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Table names follow the rest of Authway: lower case, plural, no prefix of a framework.
        builder.Entity<ApplicationUser>().ToTable("users");
        builder.Entity<IdentityRole<Guid>>().ToTable("roles");
        builder.Entity<IdentityUserRole<Guid>>().ToTable("user_roles");
        builder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
        builder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
        builder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");
        builder.Entity<IdentityRoleClaim<Guid>>().ToTable("role_claims");
        builder.Entity<DataProtectionKey>().ToTable("data_protection_keys");
    }
}
