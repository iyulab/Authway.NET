using System.Text.Json;

namespace Authway.Server;

/// <summary>What every administration call does with the request it is given.</summary>
internal static class AdminRequest
{
    /// <summary>
    /// The tenant a call names — in the body and in <c>X-Tenant-ID</c>, which must agree — is the one
    /// tenant this installation has, or it does not exist. A call that names none is about it too: the
    /// contract asks a caller to name a tenant only when it administers several.
    /// </summary>
    internal static IResult? TenantRefusal(HttpContext context, JsonElement? body)
    {
        var named = new List<string>();
        if (body is { } b && String(b, "tenant_id") is { Length: > 0 } fromBody)
        {
            named.Add(fromBody);
        }

        if (context.Request.Headers["X-Tenant-ID"].ToString() is { Length: > 0 } fromHeader)
        {
            named.Add(fromHeader);
        }

        if (context.Request.Query["tenant_id"].ToString() is { Length: > 0 } fromQuery)
        {
            named.Add(fromQuery);
        }

        var theTenant = AdminEndpoints.DefaultTenantId.ToString();
        if (named.Count > 1 && named.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1 && body is not null)
        {
            return Refuse("invalid_request", "The body and the X-Tenant-ID header name different tenants.", "tenant_id");
        }

        return named.Any(n => !string.Equals(n, theTenant, StringComparison.OrdinalIgnoreCase))
            ? Problems.Refuse(StatusCodes.Status404NotFound, "not_found", "There is no such tenant.")
            : null;
    }

    internal static async Task<(JsonElement? Body, IResult? Refusal)> ReadBodyAsync(HttpRequest request)
    {
        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (null, Refuse("invalid_request", "The body must be a JSON object."));
            }

            return (document.RootElement.Clone(), null);
        }
        catch (JsonException)
        {
            return (null, Refuse("invalid_request", "The body is not valid JSON."));
        }
    }

    /// <summary>
    /// Reads a body that may be absent: no body at all, or only whitespace, is no body and no refusal.
    /// A body that is there must be a JSON object, as in <see cref="ReadBodyAsync"/>.
    /// </summary>
    internal static async Task<(JsonElement? Body, IResult? Refusal)> ReadOptionalBodyAsync(HttpRequest request)
    {
        using var reader = new StreamReader(request.Body, leaveOpen: true);
        var text = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(text))
        {
            return (null, null);
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object
                ? (document.RootElement.Clone(), null)
                : (null, Refuse("invalid_request", "The body must be a JSON object."));
        }
        catch (JsonException)
        {
            return (null, Refuse("invalid_request", "The body is not valid JSON."));
        }
    }

    internal static IResult Refuse(string code, string detail, string? field = null) =>
        Problems.Refuse(StatusCodes.Status400BadRequest, code, detail, field: field);

    internal static string? String(JsonElement body, string name) =>
        body.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    internal static bool? Bool(JsonElement body, string name) =>
        body.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;
}
