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

    private sealed record Entry(Flow Flow, bool Completed, int Failures = 0, string? SignedInAs = null, DateTimeOffset? SignedInAt = null);

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

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _holds = new();

    public async Task<IDisposable> HoldAsync(string id)
    {
        // Only a flow that exists has a hold: an id someone made up costs nothing.
        if (!_flows.ContainsKey(id))
        {
            return NoHold.Instance;
        }

        var gate = _holds.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        return new Hold(gate);
    }

    private sealed class Hold(SemaphoreSlim gate) : IDisposable
    {
        public void Dispose() => gate.Release();
    }

    private sealed class NoHold : IDisposable
    {
        public static readonly NoHold Instance = new();

        public void Dispose()
        {
        }
    }

    public void SignedIn(string id, string subject)
    {
        if (_flows.TryGetValue(id, out var entry))
        {
            _flows[id] = entry with { Completed = true, SignedInAs = subject, SignedInAt = time.GetUtcNow() };
        }
    }

    public bool TryFindSignedIn(string id, out Flow? flow, out string? subject)
    {
        flow = null;
        subject = null;
        if (!_flows.TryGetValue(id, out var entry)
            || entry.Flow.Kind != FlowKind.Login
            || entry.SignedInAs is null
            || entry.SignedInAt is not { } at
            || time.GetUtcNow() - at >= IFlowStore.SignInRemembered
            // Guessing at the flow is capped here as it is while the flow is open.
            || entry.Failures >= IFlowStore.MaxFailures)
        {
            return false;
        }

        flow = entry.Flow;
        subject = entry.SignedInAs;
        return true;
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
                _holds.TryRemove(id, out _);
            }
        }
    }
}
