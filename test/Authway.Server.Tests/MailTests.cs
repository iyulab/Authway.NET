using System.Text.Json;
using Authway.Server.Mail;

namespace Authway.Server.Tests;

/// <summary>
/// The messages the server sends are the shared message files rendered by an engine of its own, so the
/// text must come out exactly as the other implementations render it — <c>packages/mail/golden.json</c>
/// holds what they render to.
/// </summary>
public sealed class MailTests
{
    private static readonly string[] English = ["en"];
    private static readonly string[] Korean = ["ko"];

    private static string Lines(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static Dictionary<string, object?> NoValues() => [];

    [Fact]
    public void EveryGoldenCase_RendersToExactlyTheSharedText()
    {
        using var golden = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "mail-golden.json")));
        var cases = golden.RootElement.EnumerateArray().ToList();
        Assert.NotEmpty(cases);

        foreach (var c in cases)
        {
            var label = $"{c.GetProperty("name").GetString()} ({c.GetProperty("locale").GetString()})";
            var values = c.GetProperty("vars").EnumerateObject().ToDictionary(
                p => p.Name,
                p => p.Value.ValueKind switch
                {
                    JsonValueKind.True => (object?)true,
                    JsonValueKind.False => false,
                    _ => p.Value.GetString(),
                });

            var rendered = Messages.Render(c.GetProperty("message").GetString()!, c.GetProperty("locale").GetString(), values);

            Assert.True(c.GetProperty("subject").GetString() == rendered.Subject, $"subject of {label}");
            Assert.True(Lines(c.GetProperty("text").GetString()!) == Lines(rendered.Text), $"text of {label}");
            Assert.True(Lines(c.GetProperty("html").GetString()!) == Lines(rendered.Html), $"HTML of {label}");
        }
    }

    [Fact]
    public void TheLanguagesAreTheSharedLocaleFiles()
    {
        Assert.Equal(["en", "ko"], Messages.Locales());
    }

    [Theory]
    [InlineData("ko", "ko")]
    [InlineData("en-US", "en")]
    [InlineData("ko-KR,ko;q=0.9,en;q=0.8", "ko")]
    [InlineData("fr-FR,fr;q=0.9,en;q=0.8", "en")]
    [InlineData("en;q=0.5,ko;q=0.9", "ko")]
    [InlineData("ko;q=0,en", "en")]
    [InlineData("de,fr", "en")]
    [InlineData("*", "en")]
    [InlineData("", "en")]
    [InlineData(null, "en")]
    [InlineData("KO_kr", "ko")]
    public void ALanguagePreference_BecomesALocale(string? preference, string expected)
    {
        Assert.Equal(expected, Messages.Negotiate(preference));
    }

    [Fact]
    public void ALinkThatIsNotAWebAddress_IsRefused()
    {
        var values = new Dictionary<string, object?> { ["link"] = "javascript:alert(1)", ["organization"] = "Acme" };

        Assert.Throws<FormatException>(() => Messages.Render("verification", "en", values));
    }

    [Fact]
    public void AMessageThatDoesNotExist_IsAnError_NotAnEmptyMail()
    {
        Assert.ThrowsAny<Exception>(() => Messages.Render("nope", "en", NoValues()));
    }

    [Theory]
    [InlineData("Hi {{name}}", "<b>&\"'", "Hi &lt;b&gt;&amp;&#34;&#39;")]
    [InlineData("Hi {{{name}}}", "<b>&\"'", "Hi <b>&\"'")]
    [InlineData("Hi {{& name}}", "<b>", "Hi <b>")]
    [InlineData("a{{! a comment }}b", "x", "ab")]
    public void AVariable_IsEscapedOrNot(string template, string value, string expected)
    {
        var data = new Dictionary<string, object?> { ["name"] = value };

        Assert.Equal(expected, Mustache.Render(template, data, Mustache.EscapeHtml));
    }

    [Fact]
    public void ASection_IsRenderedForATruthyValue_AndEachItemOfAList()
    {
        var data = new Dictionary<string, object?>
        {
            ["shown"] = true,
            ["hidden"] = false,
            ["empty"] = string.Empty,
            ["items"] = new List<object?> { new Dictionary<string, object?> { ["n"] = "1" }, new Dictionary<string, object?> { ["n"] = "2" } },
            ["person"] = new Dictionary<string, object?> { ["name"] = "Dana" },
        };

        Assert.Equal("[shown]", Mustache.Render("{{#shown}}[shown]{{/shown}}{{#hidden}}[hidden]{{/hidden}}{{#empty}}[empty]{{/empty}}", data, static s => s));
        Assert.Equal("<1><2>", Mustache.Render("{{#items}}<{{n}}>{{/items}}", data, static s => s));
        Assert.Equal("[none]", Mustache.Render("{{^hidden}}[none]{{/hidden}}{{^shown}}[never]{{/shown}}", data, static s => s));
        Assert.Equal("Dana", Mustache.Render("{{person.name}}", data, static s => s));
        Assert.Equal("Dana!", Mustache.Render("{{#person}}{{name}}!{{/person}}", data, static s => s));
        Assert.Equal("1,2,", Mustache.Render("{{#items}}{{n}},{{/items}}", data, static s => s));
    }

    [Fact]
    public void APartial_IsRenderedWithTheContextItIsIn()
    {
        var data = new Dictionary<string, object?> { ["name"] = "Dana" };
        var partials = new Dictionary<string, string> { ["greeting"] = "Hi {{name}}" };

        Assert.Equal("Hi Dana", Mustache.Render("{{> greeting}}", data, static s => s, partials));
        Assert.Throws<FormatException>(() => Mustache.Render("{{> missing}}", data, static s => s, partials));
    }

    [Theory]
    [InlineData("{{name")]
    [InlineData("{{#open}}never closed")]
    [InlineData("{{/closes-nothing}}")]
    [InlineData("{{}}")]
    [InlineData("{{=<% %>=}}")]
    public void ATemplateThatIsNotValid_IsRefused(string template)
    {
        Assert.Throws<FormatException>(() => Mustache.Render(template, NoValues(), static s => s));
    }

    [Fact]
    public void ThePlaceholderLanguages_AreInTheFilesNotInTheCode()
    {
        // A language is added by a file: both of these are rendered from files, in both languages.
        foreach (var locale in English.Concat(Korean))
        {
            var values = new Dictionary<string, object?> { ["link"] = "https://login.example.test/x", ["organization"] = "Acme" };
            var message = Messages.Render("reset", locale, values);
            Assert.Contains("Acme", message.Subject, StringComparison.Ordinal);
            Assert.Contains("https://login.example.test/x", message.Text, StringComparison.Ordinal);
        }
    }
}
