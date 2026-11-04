using System.Collections;
using System.Globalization;
using System.Text;

namespace Authway.Server.Mail;

/// <summary>
/// The part of Mustache the message files use: variables (<c>{{name}}</c> escaped, <c>{{{name}}}</c> and
/// <c>{{&amp; name}}</c> as they are), dotted names, sections, inverted sections, partials, comments and the
/// implicit iterator. Not here: lambdas, set delimiters, and the removal of lines holding only a section
/// tag — the files keep section tags inline, so an engine that removes such lines renders the same text.
/// It is the same engine, with the same rules, as the one in the Go implementation: the messages must
/// render to the same text in both (<c>packages/mail/golden.json</c>).
/// </summary>
public static class Mustache
{
    private const int MaxPartialDepth = 16;

    private enum Kind { Text, Escaped, Raw, Section, Inverted, Partial }

    private sealed record Node(Kind Kind, string Text, List<Node> Children);

    /// <summary>Renders <paramref name="source"/> with <paramref name="data"/>; <paramref name="escape"/> is applied to <c>{{name}}</c>.</summary>
    public static string Render(string source, IReadOnlyDictionary<string, object?> data, Func<string, string> escape, IReadOnlyDictionary<string, string>? partials = null)
    {
        var renderer = new Renderer(escape, partials ?? new Dictionary<string, string>());
        return renderer.Render(Parse(source), [data], 0);
    }

    /// <summary>The text with &amp;, &lt;, &gt;, a double and a single quote replaced — the replacements Go's <c>html.EscapeString</c> makes.</summary>
    public static string EscapeHtml(string text)
    {
        var escaped = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            escaped.Append(c switch
            {
                '&' => "&amp;",
                '\'' => "&#39;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&#34;",
                _ => c.ToString(),
            });
        }

        return escaped.ToString();
    }

    private static List<Node> Parse(string source)
    {
        var (nodes, rest) = ParseUntil(source, string.Empty);
        if (rest.Length > 0)
        {
            throw new FormatException("mustache: text after the template");
        }

        return nodes;
    }

    /// <summary>Parses up to the tag closing section <paramref name="closing"/> (empty: the end) and returns what follows it.</summary>
    private static (List<Node> Nodes, string Remainder) ParseUntil(string source, string closing)
    {
        var nodes = new List<Node>();
        while (true)
        {
            var open = source.IndexOf("{{", StringComparison.Ordinal);
            if (open < 0)
            {
                if (closing.Length > 0)
                {
                    throw new FormatException($"mustache: section \"{closing}\" is not closed");
                }

                if (source.Length > 0)
                {
                    nodes.Add(new Node(Kind.Text, source, []));
                }

                return (nodes, string.Empty);
            }

            if (open > 0)
            {
                nodes.Add(new Node(Kind.Text, source[..open], []));
            }

            source = source[(open + 2)..];
            var end = "}}";
            var triple = source.StartsWith('{');
            if (triple)
            {
                end = "}}}";
                source = source[1..];
            }

            var closeAt = source.IndexOf(end, StringComparison.Ordinal);
            if (closeAt < 0)
            {
                throw new FormatException("mustache: a tag is not closed");
            }

            var tag = source[..closeAt].Trim();
            source = source[(closeAt + end.Length)..];

            if (triple)
            {
                nodes.Add(new Node(Kind.Raw, tag, []));
                continue;
            }

            if (tag.Length == 0)
            {
                throw new FormatException("mustache: an empty tag");
            }

            var sigil = tag[0];
            var name = tag[1..].Trim();
            switch (sigil)
            {
                case '!':
                    break;
                case '&':
                    nodes.Add(new Node(Kind.Raw, name, []));
                    break;
                case '>':
                    nodes.Add(new Node(Kind.Partial, name, []));
                    break;
                case '#' or '^':
                    var (children, rest) = ParseUntil(source, name);
                    nodes.Add(new Node(sigil == '^' ? Kind.Inverted : Kind.Section, name, children));
                    source = rest;
                    break;
                case '/':
                    if (name != closing)
                    {
                        throw new FormatException($"mustache: the closing tag of \"{name}\" closes no open section");
                    }

                    return (nodes, source);
                case '=':
                    throw new FormatException("mustache: set delimiters are not supported");
                default:
                    nodes.Add(new Node(Kind.Escaped, tag, []));
                    break;
            }
        }
    }

    private sealed class Renderer(Func<string, string> escape, IReadOnlyDictionary<string, string> partials)
    {
        private readonly Dictionary<string, List<Node>> _parsed = [];

        public string Render(List<Node> nodes, List<object?> stack, int depth)
        {
            var output = new StringBuilder();
            foreach (var node in nodes)
            {
                switch (node.Kind)
                {
                    case Kind.Text:
                        output.Append(node.Text);
                        break;
                    case Kind.Escaped:
                        output.Append(escape(StringOf(Lookup(stack, node.Text))));
                        break;
                    case Kind.Raw:
                        output.Append(StringOf(Lookup(stack, node.Text)));
                        break;
                    case Kind.Section:
                        var value = Lookup(stack, node.Text);
                        if (!Truthy(value))
                        {
                            break;
                        }

                        IEnumerable<object?> items = value is IList list ? list.Cast<object?>() : [value];
                        foreach (var item in items)
                        {
                            output.Append(Render(node.Children, [.. stack, item], depth));
                        }

                        break;
                    case Kind.Inverted:
                        if (!Truthy(Lookup(stack, node.Text)))
                        {
                            output.Append(Render(node.Children, stack, depth));
                        }

                        break;
                    case Kind.Partial:
                        if (depth >= MaxPartialDepth)
                        {
                            throw new FormatException($"mustache: partials nested deeper than {MaxPartialDepth}");
                        }

                        output.Append(Render(PartialOf(node.Text), stack, depth + 1));
                        break;
                }
            }

            return output.ToString();
        }

        private List<Node> PartialOf(string name)
        {
            if (_parsed.TryGetValue(name, out var parsed))
            {
                return parsed;
            }

            if (!partials.TryGetValue(name, out var source))
            {
                throw new FormatException($"mustache: no partial \"{name}\"");
            }

            return _parsed[name] = Parse(source);
        }
    }

    /// <summary>
    /// Resolves a name against the context stack: "." is the innermost context; the first part of a
    /// dotted name is looked up from the innermost context outwards, the rest within what it found.
    /// </summary>
    private static object? Lookup(List<object?> stack, string name)
    {
        if (name == ".")
        {
            return stack.Count == 0 ? null : stack[^1];
        }

        var parts = name.Split('.');
        object? value = null;
        var found = false;
        for (var i = stack.Count - 1; i >= 0 && !found; i--)
        {
            if (stack[i] is IReadOnlyDictionary<string, object?> context)
            {
                found = context.TryGetValue(parts[0], out value);
            }
        }

        if (!found)
        {
            return null;
        }

        foreach (var part in parts.Skip(1))
        {
            if (value is not IReadOnlyDictionary<string, object?> inner)
            {
                return null;
            }

            inner.TryGetValue(part, out value);
        }

        return value;
    }

    private static bool Truthy(object? value) => value switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        IList list => list.Count > 0,
        _ => true,
    };

    private static string StringOf(object? value) => value switch
    {
        null => string.Empty,
        string s => s,
        bool b => b ? "true" : "false",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };
}
