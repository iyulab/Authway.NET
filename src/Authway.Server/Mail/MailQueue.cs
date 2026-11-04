using System.Threading.Channels;

namespace Authway.Server.Mail;

/// <summary>
/// Hands messages to the mail server after the answer has gone. A request that asks for a message to
/// be sent to an address it names answers the same whether the address has an account, and that has to
/// hold for how long the answer takes too: a call that waits on the mail server only when there is an
/// account tells a caller which addresses are registered.
/// </summary>
internal sealed partial class MailQueue(ILogger<MailQueue> logger, IServiceScopeFactory scopes) : BackgroundService
{
    private const int Capacity = 1000;

    private readonly Channel<(string Kind, Func<IServiceProvider, CancellationToken, Task> Send)> _jobs =
        Channel.CreateBounded<(string, Func<IServiceProvider, CancellationToken, Task>)>(new BoundedChannelOptions(Capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

    /// <summary>
    /// Queues work that ends in a message, run one at a time with a scope of its own, which also keeps what it
    /// reads and writes from racing with the next. Work that cannot be queued (the queue is full) is dropped and
    /// logged, never waited for.
    /// </summary>
    public void Enqueue(string kind, Func<IServiceProvider, CancellationToken, Task> send)
    {
        if (!_jobs.Writer.TryWrite((kind, send)))
        {
            Dropped(logger, kind);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var (kind, send) in _jobs.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                using var scope = scopes.CreateScope();
                await send(scope.ServiceProvider, stoppingToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                Failed(logger, exception, kind);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "A {Kind} message could not be sent")]
    private static partial void Failed(ILogger logger, Exception exception, string kind);

    [LoggerMessage(Level = LogLevel.Error, Message = "A {Kind} message was dropped: the queue of messages waiting to be sent is full")]
    private static partial void Dropped(ILogger logger, string kind);
}
