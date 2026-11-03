using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Authway.Server.Flows;

/// <summary>
/// Keeps the flows in the memory of the process. A flow lives minutes and an
/// installation is one process, so a restart costs a person who was in the
/// middle of signing in one more start; nothing here is worth a table.
/// A finished flow is remembered for a while longer, so that its id answers
/// "expired" and not "never heard of it".
/// </summary>
public sealed class MemoryFlowStore(TimeProvider time) : IFlowStore
{
    /// <summary>How long a person has to sign in once the application sent them.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    /// <summary>How long an id is remembered after the flow ended.</summary>
    private static readonly TimeSpan Remembered = TimeSpan.FromHours(1);

    private sealed record Entry(LoginFlow Flow, bool Completed);

    private readonly ConcurrentDictionary<string, Entry> _flows = new();

    public LoginFlow Open(string clientId, string clientName, IReadOnlyList<string> requestedScope, string resumeUrl, FlowHints hints)
    {
        Forget();
        var flow = new LoginFlow(
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(24)),
            clientId,
            clientName,
            requestedScope,
            resumeUrl,
            hints,
            time.GetUtcNow().Add(Lifetime));
        _flows[flow.Id] = new Entry(flow, Completed: false);
        return flow;
    }

    public FlowState Find(string id, out LoginFlow? flow)
    {
        flow = null;
        if (!_flows.TryGetValue(id, out var entry))
        {
            return FlowState.Unknown;
        }

        if (entry.Completed || time.GetUtcNow() >= entry.Flow.ExpiresAt)
        {
            return FlowState.Expired;
        }

        flow = entry.Flow;
        return FlowState.Open;
    }

    public void Complete(string id)
    {
        if (_flows.TryGetValue(id, out var entry))
        {
            _flows[id] = entry with { Completed = true };
        }
    }

    private void Forget()
    {
        var cutoff = time.GetUtcNow() - Remembered;
        foreach (var (id, entry) in _flows)
        {
            if (entry.Flow.ExpiresAt < cutoff)
            {
                _flows.TryRemove(id, out _);
            }
        }
    }
}
