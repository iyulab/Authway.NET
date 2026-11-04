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

    private sealed record Entry(Flow Flow, bool Completed, int Failures = 0);

    private readonly ConcurrentDictionary<string, Entry> _flows = new();

    public Flow Open(FlowKind kind, string clientId, string clientName, IReadOnlyList<string> requestedScope, string continueTo, FlowHints hints, string? subject = null, string? rejectTo = null)
    {
        Forget();
        var flow = new Flow(
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(24)),
            kind,
            clientId,
            clientName,
            requestedScope,
            continueTo,
            hints,
            time.GetUtcNow(),
            time.GetUtcNow().Add(Lifetime),
            subject,
            rejectTo);
        _flows[flow.Id] = new Entry(flow, Completed: false);
        return flow;
    }

    public FlowState Find(string id, FlowKind kind, out Flow? flow)
    {
        flow = null;
        if (!_flows.TryGetValue(id, out var entry) || entry.Flow.Kind != kind)
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

    public bool Fail(string id)
    {
        var ended = false;
        _flows.AddOrUpdate(
            id,
            _ => throw new InvalidOperationException("The flow does not exist."),
            (_, entry) =>
            {
                var failures = entry.Failures + 1;
                ended = failures >= IFlowStore.MaxFailures;
                return entry with { Failures = failures, Completed = entry.Completed || ended };
            });
        return ended;
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
