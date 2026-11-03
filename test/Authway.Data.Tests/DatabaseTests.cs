using Authway.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Authway.Data.Tests;

/// <summary>
/// What the data layer must do on every database an installation can run on.
/// Each provider's fixture supplies an empty database; the same tests run on
/// both.
/// </summary>
public abstract class DatabaseTests(IDatabaseFixture database)
{
    private AuthwayDbContext NewContext() => new(database.Options());

    [Fact]
    public async Task Migrations_BuildTheSchemaOnAnEmptyDatabase_AndAgainWithoutChange()
    {
        await using var first = NewContext();
        await first.Database.MigrateAsync();
        await first.Database.MigrateAsync();

        Assert.Empty(await first.Database.GetPendingMigrationsAsync());
        Assert.NotEmpty(await first.Database.GetAppliedMigrationsAsync());
        Assert.True(await first.DataProtectionKeys.CountAsync() >= 0, "the key table is there");
    }

    [Fact]
    public void Migrations_MatchTheModel_NothingIsPendingToBeScaffolded()
    {
        using var context = NewContext();

        // A change to the model without a migration for this provider fails here,
        // not on the first installation that needs it.
        Assert.False(context.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task DataProtectionKeys_LiveInTheDatabase_SoARestartedProcessReadsWhatTheLastOneProtected()
    {
        await using (var context = NewContext())
        {
            await context.Database.MigrateAsync();
        }

        ServiceProvider Process() => new ServiceCollection()
            .AddScoped(_ => NewContext())
            .AddDataProtection()
            .SetApplicationName("authway-data-tests")
            .PersistKeysToDbContext<AuthwayDbContext>()
            .Services.BuildServiceProvider();

        string sealedText;
        using (var first = Process())
        {
            sealedText = first.GetRequiredService<IDataProtectionProvider>().CreateProtector("test").Protect("a secret");
        }

        using var second = Process();
        var opened = second.GetRequiredService<IDataProtectionProvider>().CreateProtector("test").Unprotect(sealedText);

        Assert.Equal("a secret", opened);
        await using var check = NewContext();
        Assert.True(await check.DataProtectionKeys.AnyAsync());
    }
}
