using Authway.Server.Flows;

namespace Authway.Server.Tests;

/// <summary>What a flow id stands for as time passes, without a database or a server.</summary>
public class MemoryFlowStoreTests
{
    private static readonly FlowHints NoHints = new(null, null, []);

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 4, 9, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private static Flow Open(MemoryFlowStore store, FlowKind kind = FlowKind.Login) =>
        store.Open(kind, "app", "An application", ["openid"], "/connect/authorize?client_id=app", NoHints);

    [Fact]
    public void AnIdNobodyOpened_IsUnknown()
    {
        var store = new MemoryFlowStore(new Clock());

        Assert.Equal(FlowState.Unknown, store.Find("nothing", FlowKind.Login, out var flow));
        Assert.Null(flow);
    }

    [Fact]
    public void AFlowIsOpenUntilItIsCompletedOrRunsOut()
    {
        var clock = new Clock();
        var store = new MemoryFlowStore(clock);
        var opened = Open(store);

        Assert.Equal(FlowState.Open, store.Find(opened.Id, FlowKind.Login, out var found));
        Assert.Equal(opened, found);

        clock.Advance(MemoryFlowStore.Lifetime - TimeSpan.FromSeconds(1));
        Assert.Equal(FlowState.Open, store.Find(opened.Id, FlowKind.Login, out _));

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(FlowState.Expired, store.Find(opened.Id, FlowKind.Login, out found));
        Assert.Null(found);
    }

    [Fact]
    public void ACompletedFlow_IsExpired_NotUnknown()
    {
        var store = new MemoryFlowStore(new Clock());
        var opened = Open(store);

        store.Complete(opened.Id);

        Assert.Equal(FlowState.Expired, store.Find(opened.Id, FlowKind.Login, out _));
    }

    [Fact]
    public void AnEndedFlowIsRememberedForAWhile_ThenForgotten()
    {
        var clock = new Clock();
        var store = new MemoryFlowStore(clock);
        var ended = Open(store);
        store.Complete(ended.Id);

        clock.Advance(MemoryFlowStore.Lifetime + TimeSpan.FromMinutes(30));
        Open(store);
        Assert.Equal(FlowState.Expired, store.Find(ended.Id, FlowKind.Login, out _));

        clock.Advance(TimeSpan.FromHours(1));
        Open(store);
        Assert.Equal(FlowState.Unknown, store.Find(ended.Id, FlowKind.Login, out _));
    }

    [Fact]
    public void AFlowIsOnlyTheKindOfFlowItWasOpenedAs()
    {
        var store = new MemoryFlowStore(new Clock());
        var signingOut = Open(store, FlowKind.Logout);

        Assert.Equal(FlowState.Unknown, store.Find(signingOut.Id, FlowKind.Login, out _));
        Assert.Equal(FlowState.Open, store.Find(signingOut.Id, FlowKind.Logout, out _));
    }

    [Fact]
    public void AFlowEndsWhenItHasBeenAnsweredWrongTooOften()
    {
        var store = new MemoryFlowStore(new Clock());
        var opened = Open(store);

        for (var failure = 1; failure < IFlowStore.MaxFailures; failure++)
        {
            Assert.False(store.Fail(opened.Id));
            Assert.Equal(FlowState.Open, store.Find(opened.Id, FlowKind.Login, out _));
        }

        Assert.True(store.Fail(opened.Id));
        Assert.Equal(FlowState.Expired, store.Find(opened.Id, FlowKind.Login, out _));
    }

    [Fact]
    public void ASignedInFlow_IsRememberedForWhomItSignedIn_UntilItRunsOutOrIsGuessedAt()
    {
        var clock = new Clock();
        var store = new MemoryFlowStore(clock);
        var opened = Open(store);

        Assert.False(store.TryFindSignedIn(opened.Id, out _, out _), "an open flow was signed in by no one");
        store.SignedIn(opened.Id, "person");
        Assert.Equal(FlowState.Expired, store.Find(opened.Id, FlowKind.Login, out _));
        Assert.True(store.TryFindSignedIn(opened.Id, out var flow, out var subject));
        Assert.Equal(opened, flow);
        Assert.Equal("person", subject);

        var other = Open(store);
        store.Complete(other.Id);
        Assert.False(store.TryFindSignedIn(other.Id, out _, out _), "a flow completed any other way signed in no one");

        // Guessing at a signed-in flow ends as it does at an open one.
        for (var i = 0; i < IFlowStore.MaxFailures; i++)
        {
            store.Fail(opened.Id);
        }

        Assert.False(store.TryFindSignedIn(opened.Id, out _, out _));

        var later = Open(store);
        store.SignedIn(later.Id, "person");
        clock.Advance(IFlowStore.SignInRemembered);
        Assert.False(store.TryFindSignedIn(later.Id, out _, out _));
    }

    [Fact]
    public void EveryFlowGetsAnIdOfItsOwn()
    {
        var store = new MemoryFlowStore(new Clock());

        var ids = Enumerable.Range(0, 200).Select(_ => Open(store).Id).ToHashSet();

        Assert.Equal(200, ids.Count);
        Assert.All(ids, id => Assert.True(id.Length >= 32, "the id carries enough randomness to not be guessed"));
    }
}
