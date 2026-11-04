namespace Authway.Server.Flows;

/// <summary>
/// What an application's authorization request asked of the sign-in screen,
/// which otherwise only has the flow id. None of it decides anything.
/// </summary>
public sealed record FlowHints(string? SignInMethod, string? LoginHint, IReadOnlyList<string> UiLocales);

/// <summary>What a flow is waiting for the person to do.</summary>
public enum FlowKind
{
    /// <summary>Sign in.</summary>
    Login,

    /// <summary>Sign out.</summary>
    Logout,

    /// <summary>Say what an application may do with the account.</summary>
    Consent,
}

/// <summary>
/// Something that is waiting for the person: the request that started it, kept
/// so that the browser can be sent on to where it was going once the person has
/// answered. The id is opaque to the screen, which only ever hands it back.
/// </summary>
/// <param name="Id">What the screen holds on to.</param>
/// <param name="Kind">What the flow waits for.</param>
/// <param name="ClientId">The application the person came from.</param>
/// <param name="ClientName">What to call it.</param>
/// <param name="RequestedScope">What the application asked for.</param>
/// <param name="ContinueTo">Where the browser goes when the flow is answered: back to the authorization request, or on to the application after a sign-out.</param>
/// <param name="Hints">What the request asked of the screen.</param>
/// <param name="OpenedAt">When the flow was opened: a session that began before it is not an answer to it.</param>
/// <param name="ExpiresAt">When the person has run out of time.</param>
/// <param name="Subject">Who the flow is asking, when it asks one person in particular.</param>
/// <param name="RejectTo">Where the browser goes when the person says no: back to the application, with the error.</param>
public sealed record Flow(
    string Id,
    FlowKind Kind,
    string ClientId,
    string ClientName,
    IReadOnlyList<string> RequestedScope,
    string ContinueTo,
    FlowHints Hints,
    DateTimeOffset OpenedAt,
    DateTimeOffset ExpiresAt,
    string? Subject = null,
    string? RejectTo = null);

/// <summary>What a flow id stands for.</summary>
public enum FlowState
{
    /// <summary>No flow was ever opened under this id.</summary>
    Unknown,

    /// <summary>The flow was completed, or ran out of time.</summary>
    Expired,

    /// <summary>The flow is waiting for the person.</summary>
    Open,
}

/// <summary>Where the flows that are waiting for a person are kept.</summary>
public interface IFlowStore
{
    /// <summary>Opens a flow for the request and returns it.</summary>
    Flow Open(FlowKind kind, string clientId, string clientName, IReadOnlyList<string> requestedScope, string continueTo, FlowHints hints, string? subject = null, string? rejectTo = null);

    /// <summary>
    /// Says what the id stands for and, for an open flow of that kind, returns
    /// it. An id of another kind of flow is not one this caller opened.
    /// </summary>
    FlowState Find(string id, FlowKind kind, out Flow? flow);

    /// <summary>Ends a flow: it was completed, and cannot be used again.</summary>
    void Complete(string id);
}
