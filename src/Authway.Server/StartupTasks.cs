using Authway.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// Brings the database to the schema this build runs on when the server starts, as the other
/// Authway server does: one process and one database is the whole installation, and nobody has
/// a migration step to forget. Turn it off (<c>Authway:Database:MigrateOnStart=false</c>) where the
/// schema is managed by other means.
/// </summary>
internal sealed class MigrateOnStart(IServiceScopeFactory scopes) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AuthwayDbContext>().Database.MigrateAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// For a developer who wants to see the screens work: an application and a person to sign in as
/// (<c>Authway:Dev:Seed=true</c>, development only). The credentials are in the open on purpose;
/// this never runs outside development.
/// </summary>
internal sealed class DevSeed(IServiceScopeFactory scopes, IConfiguration configuration) : IHostedService
{
    public const string ClientId = "dev-app";
    public const string Address = "dev@example.test";
    public const string Password = "Correct-Horse-9";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var callback = configuration["Authway:Dev:RedirectUri"] ?? "http://127.0.0.1:5198/callback";
        if (await applications.FindByClientIdAsync(ClientId, cancellationToken) is null)
        {
            await applications.CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = ClientId,
                    ClientType = ClientTypes.Public,
                    ConsentType = configuration.GetValue("Authway:Dev:AskConsent", false) ? ConsentTypes.Explicit : ConsentTypes.Implicit,
                    DisplayName = "Development application",
                    RedirectUris = { new Uri(callback) },
                    PostLogoutRedirectUris = { new Uri(callback) },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.EndSession,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    },
                    Requirements = { Requirements.Features.ProofKeyForCodeExchange },
                },
                cancellationToken);
        }

        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.FindByEmailAsync(Address) is null)
        {
            await users.CreateAsync(new ApplicationUser { UserName = Address, Email = Address, DisplayName = "Development Person" }, Password);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
