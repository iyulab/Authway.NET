using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace Authway.Server.Mail;

/// <summary>One rendered message: its subject, an HTML body and a plain-text body.</summary>
public sealed record Message(string Subject, string Html, string Text);

/// <summary>
/// Authway's messages, rendered from the files of <c>packages/mail</c> — the same files every Authway
/// implementation renders (that package's README describes them) — which are built into the server.
/// </summary>
public static class Messages
{
    /// <summary>The language a message is written in when no other is asked for, or the one asked for has no strings.</summary>
    public const string DefaultLocale = "en";

    private const string Prefix = "mail/";

    private static readonly Assembly Source = typeof(Messages).Assembly;

    /// <summary>The languages a message can be written in: one per locale file, in alphabetical order.</summary>
    public static IReadOnlyList<string> Locales() =>
    [
        .. Source.GetManifestResourceNames()
            .Where(n => n.StartsWith(Prefix + "locales/", StringComparison.Ordinal) && n.EndsWith(".json", StringComparison.Ordinal))
            .Select(n => n[(Prefix + "locales/").Length..^".json".Length])
            .Order(StringComparer.Ordinal),
    ];

    /// <summary>
    /// Picks the locale for a language preference: an Accept-Language header (<c>ko-KR,ko;q=0.9,en;q=0.8</c>),
    /// or a single tag a person chose (<c>ko</c>, <c>en-US</c>). The best-ranked tag whose language has a
    /// locale wins, so a region tag matches its language; a tag of weight 0 is refused, the way the header
    /// defines it. Nothing usable gives <see cref="DefaultLocale"/>.
    /// </summary>
    public static string Negotiate(string? preference)
    {
        var supported = Locales().ToHashSet(StringComparer.Ordinal);
        var tags = new List<(string Language, double Weight)>();
        foreach (var part in (preference ?? string.Empty).Split(','))
        {
            var fields = part.Split(';');
            var tag = fields[0].Trim().ToLowerInvariant();
            if (tag.Length == 0 || tag == "*")
            {
                continue;
            }

            var weight = 1.0;
            foreach (var parameter in fields.Skip(1))
            {
                var pair = parameter.Trim().Split('=', 2);
                if (pair.Length == 2 && pair[0].Trim().Equals("q", StringComparison.OrdinalIgnoreCase)
                    && double.TryParse(pair[1].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
                {
                    weight = parsed;
                }
            }

            if (weight <= 0)
            {
                continue;
            }

            tags.Add((tag.Replace('_', '-').Split('-')[0], weight));
        }

        // Highest weight first; equal weights keep the order they were written in (OrderBy is stable).
        foreach (var (language, _) in tags.OrderByDescending(t => t.Weight))
        {
            if (supported.Contains(language))
            {
                return language;
            }
        }

        return DefaultLocale;
    }

    /// <summary>
    /// Renders the message <paramref name="name"/> in <paramref name="locale"/> (a tag or an Accept-Language
    /// value) with the values in <paramref name="values"/>. An empty value counts as absent, so a section on
    /// it is skipped. A <c>link</c> must be an absolute http or https address. A message that fails to
    /// render is an error, never a partial body: a partial body would still be sent.
    /// </summary>
    public static Message Render(string name, string? locale, IReadOnlyDictionary<string, object?> values)
    {
        locale = Negotiate(locale);
        var data = new Dictionary<string, object?>();
        foreach (var (key, value) in values)
        {
            if (value is string { Length: 0 })
            {
                continue;
            }

            data[key] = value;
        }

        if (data.TryGetValue("link", out var link) && link is string address
            && !(Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" && uri.Host.Length > 0))
        {
            throw new FormatException($"mail: {name}: the link is not an http(s) address");
        }

        var strings = StringsFor(name, locale);
        var style = StyleOf(name);

        // Strings are templates too (a subject naming the organization, a headline for a new user):
        // rendered as text first, then escaped where the HTML body puts them.
        var rendered = new Dictionary<string, object?>();
        foreach (var (key, source) in strings)
        {
            rendered[key] = Mustache.Render(source, data, static s => s);
        }

        data["t"] = rendered;
        data["style"] = style;

        var partials = PartialsFor(name);
        var html = Mustache.Render(Read("messages/layout.html"), data, Mustache.EscapeHtml, partials);
        var text = Mustache.Render(Read($"messages/{name}.txt"), data, static s => s);
        var subject = rendered.TryGetValue("subject", out var title) ? title as string : null;
        return string.IsNullOrEmpty(subject)
            ? throw new FormatException($"mail: {name}: no subject")
            : new Message(subject, html, text);
    }

    private static string Read(string file)
    {
        using var stream = Source.GetManifestResourceStream(Prefix + file)
            ?? throw new FileNotFoundException($"mail: no file {file} is built in");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>The message's own HTML body is the partial "content", beside the shared ones in <c>messages/partials/</c>.</summary>
    private static Dictionary<string, string> PartialsFor(string name)
    {
        var partials = new Dictionary<string, string> { ["content"] = Read($"messages/{name}.html") };
        var folder = Prefix + "messages/partials/";
        foreach (var resource in Source.GetManifestResourceNames().Where(n => n.StartsWith(folder, StringComparison.Ordinal)))
        {
            var file = resource[folder.Length..];
            partials[Path.GetFileNameWithoutExtension(file)] = Read("messages/partials/" + file);
        }

        return partials;
    }

    private static Dictionary<string, string> StringsFor(string name, string locale)
    {
        var all = ReadLocale(locale) ?? ReadLocale(DefaultLocale)
            ?? throw new FileNotFoundException($"mail: no locale {DefaultLocale} is built in");
        if (!all.TryGetValue(name, out var own))
        {
            throw new FormatException($"mail: no strings for {name}");
        }

        var merged = all.TryGetValue("common", out var common) ? new Dictionary<string, string>(common) : [];
        foreach (var (key, value) in own)
        {
            merged[key] = value;
        }

        return merged;
    }

    private static Dictionary<string, Dictionary<string, string>>? ReadLocale(string locale)
    {
        using var stream = Source.GetManifestResourceStream($"{Prefix}locales/{locale}.json");
        return stream is null ? null : JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(stream);
    }

    private static Dictionary<string, object?> StyleOf(string name)
    {
        using var document = JsonDocument.Parse(Read("messages/styles.json"));
        return document.RootElement.TryGetProperty(name, out var style)
            ? (Dictionary<string, object?>)Plain(style)!
            : throw new FormatException($"mail: no style for {name}");
    }

    /// <summary>JSON as the plain values the engine looks names up in: strings, booleans, numbers, lists and objects.</summary>
    private static object? Plain(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => Plain(p.Value)),
        JsonValueKind.Array => element.EnumerateArray().Select(Plain).ToList(),
        JsonValueKind.String => element.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => element.GetDouble(),
        _ => null,
    };
}
