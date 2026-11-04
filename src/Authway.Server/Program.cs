using Authway.Server.Mail;
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

        // The contract's rule for a password: its length, and nothing about what it is made of.
        options.Password.RequiredLength = InvitationPublicEndpoints.PasswordMinLength;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;

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

builder.Services.AddAuthwayMail();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower);

builder.Services.AddSingleton(TimeProvider.System);
SignInLimit.Add(builder.Services);
builder.Services.AddSingleton<IFlowStore, MemoryFlowStore>();
builder.Services.AddScoped<Consents>();

// The schema is brought up to date when the server starts (the host's configuration is read by then).
if (builder.Configuration.GetValue("Authway:Database:MigrateOnStart", true))
{
    builder.Services.AddHostedService<MigrateOnStart>();
}

if (builder.Environment.IsDevelopment() && builder.Configuration.GetValue("Authway:Dev:Seed", false))
{
    builder.Services.AddHostedService<DevSeed>();
}

builder.Services.AddAuthorization();

// A sign-in is checked against the account at every request that relies on it, not every half hour: ending
// every session of a person (POST /api/v1/logout) takes effect at once.
builder.Services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.Zero);

builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<AuthwayDbContext>().ReplaceDefaultEntities<Guid>())
    .AddServer(options =>
    {
        // The metadata is served where OpenID Connect Discovery has it and at the address of RFC 8414.
        options.SetConfigurationEndpointUris(".well-known/openid-configuration", ".well-known/oauth-authorization-server");

        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetEndSessionEndpointUris("connect/logout");

        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.OfflineAccess);

        ErrorPage.Add(options);

        // What a token says, as the discovery document advertises it.
        options.RegisterClaims(Claims.Subject, Identities.TenantId, Claims.Email, Claims.EmailVerified, Claims.Name, Claims.AuthenticationTime, Claims.AuthenticationMethodReference);

        // A client proves itself with its secret in the form of the request, as the contract says: the metadata does
        // not offer HTTP Basic, nor a signed assertion — no client can be registered to use one, and discovery says
        // only what a client can use. (It runs after the handlers that fill the document in.)
        options.AddEventHandler<OpenIddict.Server.OpenIddictServerEvents.HandleConfigurationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.TokenEndpointAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
                context.TokenEndpointAuthenticationMethods.Remove(ClientAuthenticationMethods.PrivateKeyJwt);
                context.Metadata.Remove("token_endpoint_auth_signing_alg_values_supported");

                // What this server does not do is said, not left out: no front-channel logout, no request objects by reference.
                context.Metadata["frontchannel_logout_supported"] = false;
                context.Metadata["request_uri_parameter_supported"] = false;
                return default;
            }).SetOrder(int.MaxValue - 1));

        // A refresh token is used once: the one that was exchanged is not accepted again, not even for a
        // while (the default leeway lets a retry through, and a stolen token with it).
        options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

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
    })
    // The access tokens this server issued, checked where a route of its own asks for the person's token; a token
    // that was revoked, or whose authorization was, is not accepted.
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
        options.EnableTokenEntryValidation();
        options.EnableAuthorizationEntryValidation();
    });

var app = builder.Build();

LoginUi.Use(app);

// What describes this installation is readable from any page.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/.well-known", StringComparison.Ordinal))
    {
        context.Response.Headers.AccessControlAllowOrigin = "*";
    }

    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "authway" }));

app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], AuthorizationEndpoint.HandleAsync).DisableAntiforgery();
app.MapPost("/connect/token", TokenEndpoint.HandleAsync).DisableAntiforgery();
app.MapMethods("/connect/userinfo", [HttpMethods.Get, HttpMethods.Post], UserInfoEndpoint.HandleAsync).DisableAntiforgery();
app.MapMethods("/connect/logout", [HttpMethods.Get, HttpMethods.Post], EndSessionEndpoint.HandleAsync).DisableAntiforgery();

CapabilitiesEndpoint.Map(app);
BootstrapConfig.Map(app);
LoginFlowEndpoints.Map(app);
LogoutFlowEndpoints.Map(app);
ConsentFlowEndpoints.Map(app);
AdminEndpoints.Map(app);
InvitationPublicEndpoints.Map(app);
SignOutEverywhere.Map(app);

app.Run();

/// <summary>Makes the host reachable from the integration tests.</summary>
public partial class Program;
