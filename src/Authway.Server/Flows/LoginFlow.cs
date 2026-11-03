namespace Authway.Server.Flows;

/// <summary>
/// What an application's authorization request asked of the sign-in screen,
/// which otherwise only has the flow id. None of it decides anything.
/// </summary>
public sealed record FlowHints(string? SignInMethod, string? LoginHint, IReadOnlyList<string> UiLocales);

/// <summary>
/// A sign-in that is waiting for the person: the authorization request that
/// started it, kept so that the browser can be sent back to it once there is a
/// session. The id is opaque to the screen, which only ever hands it back.
/// </summary>
public sealed record LoginFlow(
    string Id,
    string ClientId,
    string ClientName,
    IReadOnlyList<string> RequestedScope,
    string ResumeUrl,
    FlowHints Hints,
    DateTimeOffset ExpiresAt);

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
    LoginFlow Open(string clientId, string clientName, IReadOnlyList<string> requestedScope, string resumeUrl, FlowHints hints);

    /// <summary>Says what the id stands for and, for an open flow, returns it.</summary>
    FlowState Find(string id, out LoginFlow? flow);

    /// <summary>Ends a flow: it was completed, and cannot be used again.</summary>
    void Complete(string id);
}
