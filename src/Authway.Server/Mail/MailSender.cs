using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authway.Server.Mail;

/// <summary>Sends a rendered message to one address.</summary>
public interface IMailSender
{
    /// <summary>Hands the message to the mail server; a message that could not be handed over is an exception, never a silence.</summary>
    Task SendAsync(string recipient, Message message, CancellationToken cancellationToken = default);
}

/// <summary>
/// Sends through an SMTP server: <c>Authway:Mail:Smtp:Host</c> (with <c>Port</c> 25, <c>User</c>,
/// <c>Password</c> and <c>Tls</c> as the server needs them) and the sender's address
/// <c>Authway:Mail:From</c>. Without a host no mail is sent: an installation that has none says so when
/// something asks for mail, instead of reporting a message as sent that was not.
/// </summary>
internal sealed class SmtpMailSender(IConfiguration configuration) : IMailSender
{
    public async Task SendAsync(string recipient, Message message, CancellationToken cancellationToken = default)
    {
        var host = configuration["Authway:Mail:Smtp:Host"];
        if (string.IsNullOrEmpty(host))
        {
            throw new InvalidOperationException("No mail server is configured (Authway:Mail:Smtp:Host).");
        }

        var from = configuration["Authway:Mail:From"];
        if (string.IsNullOrEmpty(from))
        {
            throw new InvalidOperationException("No sender address is configured (Authway:Mail:From).");
        }

        using var mail = new MailMessage(from, recipient) { Subject = message.Subject, BodyEncoding = System.Text.Encoding.UTF8, SubjectEncoding = System.Text.Encoding.UTF8 };
        mail.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.Text, System.Text.Encoding.UTF8, MediaTypeNames.Text.Plain));
        mail.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.Html, System.Text.Encoding.UTF8, MediaTypeNames.Text.Html));

        using var client = new SmtpClient(host, configuration.GetValue("Authway:Mail:Smtp:Port", 25))
        {
            EnableSsl = configuration.GetValue("Authway:Mail:Smtp:Tls", false),
        };
        if (configuration["Authway:Mail:Smtp:User"] is { Length: > 0 } user)
        {
            client.Credentials = new NetworkCredential(user, configuration["Authway:Mail:Smtp:Password"]);
        }

        await client.SendMailAsync(mail, cancellationToken);
    }
}

/// <summary>The services that send mail.</summary>
public static class MailServices
{
    /// <summary>Adds the mail sender; a host's own <see cref="IMailSender"/> registered earlier is kept.</summary>
    public static IServiceCollection AddAuthwayMail(this IServiceCollection services)
    {
        services.TryAddSingleton<IMailSender, SmtpMailSender>();
        return services;
    }
}
