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

    /// <summary>The invitations to sign up.</summary>
    public DbSet<Invitation> Invitations => Set<Invitation>();

    /// <summary>What was done, by whom: the audit log.</summary>
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

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

        builder.Entity<Invitation>(invitation =>
        {
            invitation.ToTable("invitations");
            invitation.HasKey(i => i.Id);
            invitation.Property(i => i.Email).HasMaxLength(320);
            invitation.Property(i => i.NormalizedEmail).HasMaxLength(320);
            invitation.Property(i => i.InviterName).HasMaxLength(256);
            invitation.Property(i => i.ClientId).HasMaxLength(256);
            invitation.Property(i => i.TokenHash).HasMaxLength(64);
            invitation.Property(i => i.Status).HasMaxLength(16);
            invitation.HasIndex(i => i.TokenHash).IsUnique();
            invitation.HasIndex(i => new { i.NormalizedEmail, i.Status });
        });

        builder.Entity<AuditLog>(entry =>
        {
            entry.ToTable("audit_logs");
            entry.HasKey(e => e.Id);
            entry.Property(e => e.ActorEmail).HasMaxLength(320);
            entry.Property(e => e.ActorType).HasMaxLength(50);
            entry.Property(e => e.Action).HasMaxLength(100);
            entry.Property(e => e.Severity).HasMaxLength(20);
            entry.Property(e => e.ResourceType).HasMaxLength(100);
            entry.Property(e => e.ResourceId).HasMaxLength(255);
            entry.Property(e => e.IpAddress).HasMaxLength(45);
            entry.Property(e => e.UserAgent).HasMaxLength(512);
            // Newest first, by when, by what, by whom, by what it was about.
            entry.HasIndex(e => e.CreatedAt);
            entry.HasIndex(e => e.Action);
            entry.HasIndex(e => e.ActorId);
            entry.HasIndex(e => e.ResourceId);
        });
    }
}
