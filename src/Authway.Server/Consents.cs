using System.Collections.Immutable;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Authway.Server;

/// <summary>What a person has already said yes to for an application.</summary>
/// <param name="Scopes">The scopes the answer covers; the tokens are issued for these.</param>
/// <param name="AuthorizationId">The authorization the answer is kept in; the tokens are tied to it.</param>
internal sealed record Consent(IReadOnlyList<string> Scopes, string AuthorizationId);

/// <summary>
/// The answers people give when an application asks for access, kept as
/// OpenIddict authorizations. A permanent one is the person's "do not ask me
/// again for this application" and covers what it was granted for. One they did
/// not ask to keep is good only for the request they have just answered: the
/// browser comes back to the authorization endpoint with its id, and no other
/// request may use it.
/// </summary>
internal sealed class Consents(IOpenIddictAuthorizationManager authorizations, IOpenIddictApplicationManager applications, TimeProvider time)
{
    /// <summary>The query parameter the browser carries back to the authorization endpoint: the answer it has just given.</summary>
    public const string AnsweredParameter = "authway_consent";

    /// <summary>How long after the answer the browser has to come back with it.</summary>
    public static readonly TimeSpan JustAnswered = TimeSpan.FromMinutes(2);

    /// <summary>
    /// What the person has said yes to for this request: the answer they have just given to it
    /// (which may cover less than was asked for), or a kept answer that covers everything asked
    /// for unless the application asked to be sure. Null when there is none.
    /// </summary>
    public async Task<Consent?> FindAsync(string subject, object application, IReadOnlyList<string> requested, bool ignoreKept, string? answeredId)
    {
        var applicationId = await applications.GetIdAsync(application) ?? throw new InvalidOperationException("The application has no id.");

        if (!string.IsNullOrEmpty(answeredId))
        {
            var answered = await authorizations.FindByIdAsync(answeredId);
            if (answered is not null
                && await authorizations.GetStatusAsync(answered) == Statuses.Valid
                && await authorizations.GetSubjectAsync(answered) == subject
                && await authorizations.GetApplicationIdAsync(answered) == applicationId
                && await authorizations.GetCreationDateAsync(answered) is { } at && time.GetUtcNow() - at <= JustAnswered)
            {
                var granted = requested.Where((await authorizations.GetScopesAsync(answered)).Contains).ToList();
                if (granted.Count > 0)
                {
                    return new Consent(granted, answeredId);
                }
            }
        }

        if (ignoreKept)
        {
            return null;
        }

        await foreach (var authorization in authorizations.FindAsync(subject, applicationId, Statuses.Valid, AuthorizationTypes.Permanent, ImmutableArray<string>.Empty))
        {
            var scopes = await authorizations.GetScopesAsync(authorization);
            if (requested.All(scopes.Contains))
            {
                return new Consent(requested, await authorizations.GetIdAsync(authorization) ?? string.Empty);
            }
        }

        return null;
    }

    /// <summary>Records the answer: kept for the next time, or good for the request it answers.</summary>
    public async Task<Consent> GrantAsync(string subject, object application, IReadOnlyList<string> scopes, bool keep)
    {
        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = await applications.GetIdAsync(application),
            Subject = subject,
            Status = Statuses.Valid,
            Type = keep ? AuthorizationTypes.Permanent : AuthorizationTypes.AdHoc,
            CreationDate = time.GetUtcNow(),
        };
        descriptor.Scopes.UnionWith(scopes);

        var created = await authorizations.CreateAsync(descriptor);
        return new Consent(scopes, await authorizations.GetIdAsync(created) ?? string.Empty);
    }
}
