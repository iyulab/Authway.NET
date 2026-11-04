using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using static Authway.Server.AdminRequest;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>
/// The applications that sign people in here (<c>/api/v1/clients</c>): registered, read, changed and
/// removed by an administrator. Each is an OpenIddict application; what OpenIddict has no member for
/// (the description, the allowed origins, the sign-in methods …) is kept in its properties, so that
/// an update returns exactly what it was given. What this installation does not offer — other
/// sign-in providers, keys instead of a secret, back-channel logout, turning a client off — is refused
/// with the code the contract names, not accepted and ignored.
/// </summary>
internal static class ClientEndpoints
{
    private const int MostPerPage = 100;
    private const int DefaultPerPage = 20;

    private static readonly string[] GrantTypes = [GrantTypesOf.AuthorizationCode, GrantTypesOf.RefreshToken, GrantTypesOf.ClientCredentials];
    private static readonly string[] SignInMethods = ["email"];

    /// <summary>Everything the contract lets a client say about signing in with another provider.</summary>
    private static readonly string[] ProviderMembers =
    [
        "google_oauth_enabled", "google_client_id", "google_client_secret", "google_redirect_uri",
        "github_oauth_enabled", "github_client_id", "github_client_secret",
        "microsoft_oauth_enabled", "microsoft_client_id", "microsoft_client_secret", "microsoft_tenant_id",
        "apple_oauth_enabled", "apple_client_id", "apple_team_id", "apple_key_id", "apple_private_key",
    ];

    public static void Map(RouteGroupBuilder admin)
    {
        admin.MapGet("/clients", ListAsync);
        admin.MapPost("/clients", CreateAsync);
        admin.MapGet("/clients/{id}", GetAsync);
        admin.MapPut("/clients/{id}", UpdateAsync);
        admin.MapDelete("/clients/{id}", DeleteAsync);
        admin.MapPost("/clients/{id}/regenerate-secret", RegenerateSecretAsync);
    }

    // ---- the calls ------------------------------------------------------------------------

    private static async Task<IResult> ListAsync(HttpContext context, IOpenIddictApplicationManager applications)
    {
        if (TenantRefusal(context, null) is { } refusal)
        {
            return refusal;
        }

        var query = context.Request.Query;
        var limit = Math.Clamp(int.TryParse(query["limit"], CultureInfo.InvariantCulture, out var l) ? l : DefaultPerPage, 1, MostPerPage);
        var offset = Math.Max(int.TryParse(query["offset"], CultureInfo.InvariantCulture, out var o) ? o : 0, 0);

        var all = new List<Dictionary<string, object?>>();
        await foreach (var application in applications.ListAsync())
        {
            all.Add(await ToJsonAsync(applications, application));
        }

        // Newest first; the clients registered before dates were kept come last.
        var ordered = all.OrderByDescending(c => (string)c["created_at"]!, StringComparer.Ordinal).ToList();
        return Results.Json(new Dictionary<string, object>
        {
            ["clients"] = ordered.Skip(offset).Take(limit).ToList(),
            ["total"] = ordered.Count,
            ["limit"] = limit,
            ["offset"] = offset,
        });
    }

    private static async Task<IResult> GetAsync(string id, IOpenIddictApplicationManager applications)
    {
        var (application, refusal) = await FindAsync(applications, id);
        return refusal ?? Results.Json(new { client = await ToJsonAsync(applications, application!) });
    }

    private static async Task<IResult> CreateAsync(HttpContext context, IOpenIddictApplicationManager applications)
    {
        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        if (TenantRefusal(context, body!.Value) is { } wrongTenant)
        {
            return wrongTenant;
        }

        var spec = new ClientSpec { Public = Bool(body.Value, "public") ?? false, CreatedAt = DateTimeOffset.UtcNow };
        if (Apply(spec, body.Value, creating: true) is { } refusal)
        {
            return refusal;
        }

        var clientId = String(body.Value, "client_id");
        var secret = String(body.Value, "client_secret");
        if (clientId is not null && Guid.TryParse(clientId, out _))
        {
            return Refuse("invalid_client_id", "A client_id in the form of a user id is not allowed.", "client_id");
        }

        if (spec.Public && !string.IsNullOrEmpty(secret))
        {
            return Refuse("public_client_with_secret", "A public client has no secret.", "client_secret");
        }

        if (!spec.Public && (string.IsNullOrEmpty(clientId) != string.IsNullOrEmpty(secret)) && (clientId is not null || secret is not null))
        {
            return Refuse("confidential_client_partial_credentials", "A confidential client that names its client_id names its client_secret too, and the reverse.", clientId is null ? "client_id" : "client_secret");
        }

        if (Check(spec) is { } incoherent)
        {
            return incoherent;
        }

        clientId = string.IsNullOrEmpty(clientId) ? "c-" + WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(12)) : clientId;
        if (await applications.FindByClientIdAsync(clientId) is not null)
        {
            return Problems.Refuse(StatusCodes.Status409Conflict, "client_id_taken", "That client_id is already registered.", field: "client_id");
        }

        var descriptor = new OpenIddictApplicationDescriptor { ClientId = clientId };
        if (!spec.Public)
        {
            secret = string.IsNullOrEmpty(secret) ? NewSecret() : secret;
            descriptor.ClientSecret = secret;
        }

        spec.WriteTo(descriptor);
        var created = await applications.CreateAsync(descriptor);

        var response = new Dictionary<string, object?>
        {
            ["client"] = await ToJsonAsync(applications, created),
            ["message"] = "Client registered.",
        };
        if (!spec.Public)
        {
            response["credentials"] = new Dictionary<string, object> { ["client_id"] = clientId, ["client_secret"] = secret! };
        }

        return Results.Json(response, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> UpdateAsync(string id, HttpContext context, IOpenIddictApplicationManager applications)
    {
        var (application, notFound) = await FindAsync(applications, id);
        if (notFound is not null)
        {
            return notFound;
        }

        var (body, bad) = await ReadBodyAsync(context.Request);
        if (bad is not null)
        {
            return bad;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        var spec = ClientSpec.From(descriptor);

        if (Bool(body!.Value, "public") is { } isPublic && isPublic != spec.Public)
        {
            return Refuse("invalid_request", "Whether a client is public is decided when it is registered.", "public");
        }

        if (Apply(spec, body.Value, creating: false) is { } refusal)
        {
            return refusal;
        }

        if (Check(spec) is { } incoherent)
        {
            return incoherent;
        }

        spec.WriteTo(descriptor);
        await applications.UpdateAsync(application!, descriptor);
        return Results.Json(new Dictionary<string, object?>
        {
            ["client"] = await ToJsonAsync(applications, (await applications.FindByIdAsync(id))!),
            ["sync_status"] = new Dictionary<string, object> { ["state"] = "ok" },
            ["message"] = "Client updated.",
        });
    }

    private static async Task<IResult> DeleteAsync(string id, IOpenIddictApplicationManager applications)
    {
        var (application, notFound) = await FindAsync(applications, id);
        if (notFound is not null)
        {
            return notFound;
        }

        await applications.DeleteAsync(application!);
        return Results.Json(new { message = "Client deleted." });
    }

    private static async Task<IResult> RegenerateSecretAsync(string id, IOpenIddictApplicationManager applications)
    {
        var (application, notFound) = await FindAsync(applications, id);
        if (notFound is not null)
        {
            return notFound;
        }

        if (await applications.HasClientTypeAsync(application!, ClientTypes.Public))
        {
            return Refuse("public_client_has_no_secret", "A public client has no secret to regenerate.");
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        var secret = NewSecret();
        descriptor.ClientSecret = secret;
        await applications.UpdateAsync(application!, descriptor);

        return Results.Json(new Dictionary<string, object>
        {
            ["credentials"] = new Dictionary<string, object>
            {
                ["client_id"] = (await applications.GetClientIdAsync(application!))!,
                ["client_secret"] = secret,
            },
            ["sync_status"] = new Dictionary<string, object> { ["state"] = "ok" },
            ["message"] = "Client secret regenerated.",
        });
    }

    // ---- this resource ------------------------------------------------------------------

    private static async Task<(object? Application, IResult? Refusal)> FindAsync(IOpenIddictApplicationManager applications, string id)
    {
        if (!Guid.TryParse(id, out _))
        {
            return (null, Refuse("invalid_request", "The client id is not valid."));
        }

        var application = await applications.FindByIdAsync(id);
        return application is null
            ? (null, Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "There is no such client."))
            : (application, null);
    }

    private static string NewSecret() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Takes what the request carries into the client, refusing what is not valid or not offered
    /// here. A member that is absent leaves the client as it is.
    /// </summary>
    private static IResult? Apply(ClientSpec spec, JsonElement body, bool creating)
    {
        if (creating)
        {
            if (String(body, "name") is not { Length: > 0 } name)
            {
                return Refuse("invalid_request", "A name is required.", "name");
            }

            spec.Name = name;
            if (!body.TryGetProperty("grant_types", out _))
            {
                return Refuse("invalid_request", "grant_types is required.", "grant_types");
            }

            if (!body.TryGetProperty("scopes", out _))
            {
                return Refuse("invalid_request", "scopes is required.", "scopes");
            }
        }
        else if (body.TryGetProperty("name", out var named))
        {
            if (named.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(named.GetString()))
            {
                return Refuse("invalid_request", "A name cannot be empty.", "name");
            }

            spec.Name = named.GetString()!;
        }

        if (String(body, "description") is { } description)
        {
            spec.Description = description;
        }

        if (Bool(body, "skip_consent") is { } skipConsent)
        {
            spec.SkipConsent = skipConsent;
        }

        if (Bool(body, "skip_logout_consent") is { } skipLogoutConsent)
        {
            spec.SkipLogoutConsent = skipLogoutConsent;
        }

        if (Strings(body, "redirect_uris", out var redirectUris) is { } badRedirects)
        {
            return badRedirects;
        }

        if (redirectUris is not null)
        {
            if (redirectUris.Find(u => !IsUri(u)) is { } notUri)
            {
                return Refuse("invalid_redirect_uri", $"“{notUri}” is not an absolute address.", "redirect_uris");
            }

            spec.RedirectUris = redirectUris;
        }

        if (Strings(body, "post_logout_redirect_uris", out var logoutUris) is { } badLogout)
        {
            return badLogout;
        }

        if (logoutUris is not null)
        {
            if (logoutUris.Find(u => !IsUri(u)) is { } notUri)
            {
                return Refuse("invalid_redirect_uri", $"“{notUri}” is not an absolute address.", "post_logout_redirect_uris");
            }

            spec.PostLogoutRedirectUris = logoutUris;
        }

        if (Strings(body, "allowed_origins", out var origins) is { } badOrigins)
        {
            return badOrigins;
        }

        if (origins is not null)
        {
            if (origins.Find(o => !IsOrigin(o)) is { } notOrigin)
            {
                return Refuse("invalid_request", $"“{notOrigin}” is not an origin (scheme, host and port only).", "allowed_origins");
            }

            spec.AllowedOrigins = origins;
        }

        if (Strings(body, "audience", out var audience) is { } badAudience)
        {
            return badAudience;
        }

        spec.Audience = audience ?? spec.Audience;

        if (Strings(body, "grant_types", out var grants) is { } badGrants)
        {
            return badGrants;
        }

        if (grants is not null)
        {
            if (grants.Find(g => !GrantTypes.Contains(g)) is { } notOffered)
            {
                return Refuse("unsupported_grant_type", $"The grant “{notOffered}” is not offered.", "grant_types");
            }

            spec.GrantTypes = grants.Distinct().ToList();
        }

        if (Strings(body, "scopes", out var scopes) is { } badScopes)
        {
            return badScopes;
        }

        spec.Scopes = scopes?.Distinct().ToList() ?? spec.Scopes;

        if (Strings(body, "enabled_auth_providers", out var providers) is { } badProviders)
        {
            return badProviders;
        }

        if (providers is not null)
        {
            if (providers.Count == 0)
            {
                return Refuse("invalid_enabled_auth_providers", "A client needs at least one way to sign in.", "enabled_auth_providers");
            }

            if (providers.Find(p => !SignInMethods.Contains(p)) is { } notOffered)
            {
                return Refuse("invalid_enabled_auth_providers", $"The sign-in method “{notOffered}” is not offered by this installation.", "enabled_auth_providers");
            }

            spec.SignInMethods = providers.Distinct().ToList();
        }

        foreach (var (member, set) in new (string, Action<string>)[]
        {
            ("client_uri", v => spec.ClientUri = v),
            ("logo", v => spec.Logo = v),
            ("initiate_login_uri", v => spec.InitiateLoginUri = v),
        })
        {
            if (String(body, member) is not { } address)
            {
                continue;
            }

            if (address.Length > 0 && !(Uri.TryCreate(address, UriKind.Absolute, out var parsed) && parsed.Scheme == Uri.UriSchemeHttps))
            {
                return Refuse("invalid_request", "It must be an absolute https address, or empty to clear it.", member);
            }

            set(address);
        }

        if (body.TryGetProperty("access_token_strategy", out var strategy))
        {
            var value = strategy.ValueKind == JsonValueKind.String ? strategy.GetString() : null;
            if (value is not ("" or "jwt"))
            {
                return Refuse("invalid_access_token_strategy", "This installation issues signed JWT access tokens; opaque ones are not offered.", "access_token_strategy");
            }

            spec.AccessTokenStrategy = value;
        }

        return NotOffered(body);
    }

    /// <summary>What the contract has and this installation does not: said so, not ignored.</summary>
    private static IResult? NotOffered(JsonElement body)
    {
        if (String(body, "token_endpoint_auth_method") is { } method && method != "none" && method != "client_secret_post")
        {
            return Refuse("invalid_token_endpoint_auth_method", $"Authenticating with “{method}” is not offered; a client uses its secret.", "token_endpoint_auth_method");
        }

        foreach (var member in new[] { "jwks", "jwks_uri", "token_endpoint_auth_signing_alg" })
        {
            if (body.TryGetProperty(member, out var value) && value.ValueKind is not JsonValueKind.Null && !(value.ValueKind == JsonValueKind.String && value.GetString()!.Length == 0))
            {
                return Refuse("invalid_token_endpoint_auth_method", "Keys instead of a secret are not offered.", member);
            }
        }

        // A provider this installation does not offer has no credentials to keep: every member of it is refused.
        foreach (var member in ProviderMembers)
        {
            if (body.TryGetProperty(member, out var value) && value.ValueKind is not JsonValueKind.Null and not JsonValueKind.False
                && !(value.ValueKind == JsonValueKind.String && value.GetString()!.Length == 0))
            {
                return Refuse("provider_unavailable", $"Signing in with {member[..member.IndexOf('_', StringComparison.Ordinal)]} is not offered by this installation.", member);
            }
        }

        if (String(body, "backchannel_logout_uri") is { Length: > 0 })
        {
            return Refuse("invalid_backchannel_logout_uri", "Back-channel logout is not offered by this installation.", "backchannel_logout_uri");
        }

        return Bool(body, "active") is false
            ? Refuse("invalid_request", "Turning a client off is not offered by this installation.", "active")
            : null;
    }

    /// <summary>What a client must be, taken as a whole.</summary>
    private static IResult? Check(ClientSpec spec)
    {
        if (spec.GrantTypes.Count == 0)
        {
            return Refuse("invalid_request", "A client needs at least one grant.", "grant_types");
        }

        if (spec.Public && spec.GrantTypes.Contains(GrantTypesOf.ClientCredentials))
        {
            return Refuse("public_client_with_client_credentials", "A public client has no secret to use the client_credentials grant with.", "grant_types");
        }

        if (spec.GrantTypes.Contains(GrantTypesOf.AuthorizationCode) && spec.RedirectUris.Count == 0)
        {
            return Refuse("redirect_grant_without_redirect_uris", "A client that signs people in needs at least one redirect address.", "redirect_uris");
        }

        if (spec.Public && spec.RedirectUris.Any(u => u.StartsWith("http", StringComparison.OrdinalIgnoreCase)) && spec.AllowedOrigins.Count == 0)
        {
            return Refuse("public_client_missing_allowed_origins", "A public client with a web redirect address names the origins it is served from.", "allowed_origins");
        }

        return null;
    }

    /// <summary>An array of strings, or <c>null</c> when the member is absent; anything else is refused.</summary>
    private static IResult? Strings(JsonElement body, string name, out List<string>? values)
    {
        values = null;
        if (!body.TryGetProperty(name, out var member) || member.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (member.ValueKind != JsonValueKind.Array || member.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String))
        {
            return Refuse("invalid_request", "It must be a list of strings.", name);
        }

        values = member.EnumerateArray().Select(e => e.GetString()!).ToList();
        return null;
    }

    private static bool IsUri(string value) => Uri.TryCreate(value, UriKind.Absolute, out _);

    private static bool IsOrigin(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme is "http" or "https")
        && (uri.AbsolutePath == "/" && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment))
        && !value.EndsWith('/');

    private static async Task<Dictionary<string, object?>> ToJsonAsync(IOpenIddictApplicationManager applications, object application)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        var spec = ClientSpec.From(descriptor);
        return new Dictionary<string, object?>
        {
            ["id"] = await applications.GetIdAsync(application),
            ["tenant_id"] = AdminEndpoints.DefaultTenantId.ToString(),
            ["client_id"] = descriptor.ClientId,
            ["name"] = spec.Name,
            ["description"] = spec.Description,
            ["public"] = spec.Public,
            ["system"] = false,
            ["redirect_uris"] = spec.RedirectUris,
            ["post_logout_redirect_uris"] = spec.PostLogoutRedirectUris,
            ["allowed_origins"] = spec.AllowedOrigins,
            ["audience"] = spec.Audience,
            ["token_endpoint_auth_method"] = spec.Public ? "none" : "client_secret_post",
            ["grant_types"] = spec.GrantTypes,
            ["scopes"] = spec.Scopes,
            ["enabled_auth_providers"] = spec.SignInMethods,
            ["skip_consent"] = spec.SkipConsent,
            ["skip_logout_consent"] = spec.SkipLogoutConsent,
            ["active"] = true,
            ["initiate_login_uri"] = spec.InitiateLoginUri,
            ["client_uri"] = spec.ClientUri,
            ["logo"] = spec.Logo,
            ["backchannel_logout_uri"] = string.Empty,
            ["google_oauth_enabled"] = false,
            ["github_oauth_enabled"] = false,
            ["microsoft_oauth_enabled"] = false,
            ["apple_oauth_enabled"] = false,
            ["access_token_strategy"] = string.IsNullOrEmpty(spec.AccessTokenStrategy) ? null : spec.AccessTokenStrategy,
            ["created_at"] = spec.CreatedAt.ToString("O", CultureInfo.InvariantCulture),
        };
    }

    /// <summary>The grant names the contract uses.</summary>
    private static class GrantTypesOf
    {
        public const string AuthorizationCode = "authorization_code";
        public const string RefreshToken = "refresh_token";
        public const string ClientCredentials = "client_credentials";
    }

    /// <summary>
    /// A client as the contract describes it, read from and written to the application OpenIddict
    /// keeps: the parts OpenIddict has a member for there, the others in its properties.
    /// </summary>
    private sealed class ClientSpec
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool Public { get; set; }
        public bool SkipConsent { get; set; }
        public bool SkipLogoutConsent { get; set; }
        public List<string> RedirectUris { get; set; } = [];
        public List<string> PostLogoutRedirectUris { get; set; } = [];
        public List<string> AllowedOrigins { get; set; } = [];
        public List<string> Audience { get; set; } = [];
        public List<string> GrantTypes { get; set; } = [];
        public List<string> Scopes { get; set; } = [];
        public List<string> SignInMethods { get; set; } = ["email"];
        public string ClientUri { get; set; } = string.Empty;
        public string Logo { get; set; } = string.Empty;
        public string InitiateLoginUri { get; set; } = string.Empty;
        public string? AccessTokenStrategy { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UnixEpoch;

        public static ClientSpec From(OpenIddictApplicationDescriptor descriptor)
        {
            List<string> List(string key) => descriptor.Properties.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.Array
                ? v.EnumerateArray().Select(e => e.GetString()!).ToList()
                : [];
            string Text(string key) => descriptor.Properties.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : string.Empty;

            return new ClientSpec
            {
                Name = descriptor.DisplayName ?? descriptor.ClientId ?? string.Empty,
                Description = Text("description"),
                Public = descriptor.ClientType == ClientTypes.Public,
                SkipConsent = descriptor.ConsentType == ConsentTypes.Implicit,
                SkipLogoutConsent = descriptor.Properties.TryGetValue("skip_logout_consent", out var s) && s.ValueKind == JsonValueKind.True,
                RedirectUris = descriptor.RedirectUris.Select(u => u.OriginalString).ToList(),
                PostLogoutRedirectUris = descriptor.PostLogoutRedirectUris.Select(u => u.OriginalString).ToList(),
                AllowedOrigins = List("allowed_origins"),
                Audience = List("audience"),
                GrantTypes = descriptor.Properties.ContainsKey("grant_types") ? List("grant_types") : GrantsOf(descriptor),
                Scopes = descriptor.Properties.ContainsKey("scopes") ? List("scopes") : ScopesOf(descriptor),
                SignInMethods = descriptor.Properties.ContainsKey("enabled_auth_providers") ? List("enabled_auth_providers") : ["email"],
                ClientUri = Text("client_uri"),
                Logo = Text("logo"),
                InitiateLoginUri = Text("initiate_login_uri"),
                AccessTokenStrategy = descriptor.Properties.ContainsKey("access_token_strategy") ? Text("access_token_strategy") : null,
                CreatedAt = DateTimeOffset.TryParse(Text("created_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at) ? at : DateTimeOffset.UnixEpoch,
            };
        }

        public void WriteTo(OpenIddictApplicationDescriptor descriptor)
        {
            descriptor.DisplayName = Name;
            descriptor.ClientType = Public ? ClientTypes.Public : ClientTypes.Confidential;
            descriptor.ConsentType = SkipConsent ? ConsentTypes.Implicit : ConsentTypes.Explicit;

            descriptor.RedirectUris.Clear();
            RedirectUris.ForEach(u => descriptor.RedirectUris.Add(new Uri(u)));
            descriptor.PostLogoutRedirectUris.Clear();
            PostLogoutRedirectUris.ForEach(u => descriptor.PostLogoutRedirectUris.Add(new Uri(u)));

            descriptor.Permissions.Clear();
            descriptor.Requirements.Clear();
            descriptor.Permissions.Add(Permissions.Endpoints.Token);
            if (GrantTypes.Contains(GrantTypesOf.AuthorizationCode))
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
                descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            }

            if (GrantTypes.Contains(GrantTypesOf.RefreshToken))
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            }

            if (GrantTypes.Contains(GrantTypesOf.ClientCredentials))
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            }

            foreach (var scope in Scopes)
            {
                descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
            }

            Set(descriptor, "description", Description);
            Set(descriptor, "skip_logout_consent", SkipLogoutConsent);
            Set(descriptor, "allowed_origins", AllowedOrigins);
            Set(descriptor, "audience", Audience);
            Set(descriptor, "grant_types", GrantTypes);
            Set(descriptor, "scopes", Scopes);
            Set(descriptor, "enabled_auth_providers", SignInMethods);
            Set(descriptor, "client_uri", ClientUri);
            Set(descriptor, "logo", Logo);
            Set(descriptor, "initiate_login_uri", InitiateLoginUri);
            Set(descriptor, "access_token_strategy", AccessTokenStrategy ?? string.Empty);
            Set(descriptor, "created_at", CreatedAt.ToString("O", CultureInfo.InvariantCulture));
        }

        private static void Set<T>(OpenIddictApplicationDescriptor descriptor, string key, T value) =>
            descriptor.Properties[key] = JsonSerializer.SerializeToElement(value);

        /// <summary>For an application registered without these properties (the development one).</summary>
        private static List<string> GrantsOf(OpenIddictApplicationDescriptor descriptor) =>
        [
            .. descriptor.Permissions.Contains(Permissions.GrantTypes.AuthorizationCode) ? [GrantTypesOf.AuthorizationCode] : Array.Empty<string>(),
            .. descriptor.Permissions.Contains(Permissions.GrantTypes.RefreshToken) ? [GrantTypesOf.RefreshToken] : Array.Empty<string>(),
            .. descriptor.Permissions.Contains(Permissions.GrantTypes.ClientCredentials) ? [GrantTypesOf.ClientCredentials] : Array.Empty<string>(),
        ];

        private static List<string> ScopesOf(OpenIddictApplicationDescriptor descriptor) =>
            descriptor.Permissions.Where(p => p.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal)).Select(p => p[Permissions.Prefixes.Scope.Length..]).ToList();
    }
}
