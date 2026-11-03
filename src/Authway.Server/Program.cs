using Authway.Data;
using Authway.Server;
using Authway.Server.Flows;
using Authway.Data.Postgres;
using Authway.Data.SqlServer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// The database is read when the context is first built, not here: a host that
// is started with its configuration supplied afterwards (the integration tests)
// is then configured the same way as one that reads it from the start.
builder.Services.AddDbContext<AuthwayDbContext>((services, options) =>
{
    var configuration = services.GetRequiredService<IConfiguration>();
    var provider = configuration.GetValue("Authway:Database:Provider", DatabaseProvider.PostgreSql);
    var connectionString = configuration.GetConnectionString("Authway")
        ?? throw new InvalidOperationException("ConnectionStrings:Authway is not set: Authway needs the database it stores its accounts in.");
    _ = provider switch
    {
        DatabaseProvider.PostgreSql => options.UseAuthwayPostgres(connectionString),
        DatabaseProvider.SqlServer => options.UseAuthwaySqlServer(connectionString),
        _ => throw new InvalidOperationException($"Unknown database provider {provider}."),
    };
});

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.ClaimsIdentity.UserNameClaimType = Claims.Name;
        options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
        options.ClaimsIdentity.RoleClaimType = Claims.Role;
    })
    .AddEntityFrameworkStores<AuthwayDbContext>()
    .AddDefaultTokenProviders();

// The cookie is the session: it answers 401 to a caller that is not signed in rather than
// sending it to a page, since the sign-in screen is reached by the flow, not by a redirect.
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "authway_session";
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});

builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IFlowStore, MemoryFlowStore>();

builder.Services.AddAuthorization();

builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<AuthwayDbContext>().ReplaceDefaultEntities<Guid>())
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetEndSessionEndpointUris("connect/logout");

        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.OfflineAccess);

        // Access tokens are signed JWTs a resource server reads with the published keys (the
        // contract's JwtAccessToken), not tokens only this server can open.
        options.DisableAccessTokenEncryption();

        // S256 only: a challenge sent as itself proves nothing to anyone who saw the request.
        options.Configure(server => server.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));

        if (builder.Environment.IsDevelopment())
        {
            options.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        }

        var aspNetCore = options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();

        if (builder.Environment.IsDevelopment())
        {
            // Development runs over plain http; everywhere else the server answers only over https.
            aspNetCore.DisableTransportSecurityRequirement();
        }
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "authway" }));

app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], AuthorizationEndpoint.HandleAsync).DisableAntiforgery();
app.MapPost("/connect/token", TokenEndpoint.HandleAsync).DisableAntiforgery();

LoginFlowEndpoints.Map(app);

app.Run();

/// <summary>Makes the host reachable from the integration tests.</summary>
public partial class Program;
