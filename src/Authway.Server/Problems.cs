using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Authway.Server;

/// <summary>
/// The refusals of <c>/api/v1/*</c>: RFC 9457 problem details whose
/// <c>code</c> a caller branches on and whose <c>detail</c> a person reads.
/// </summary>
internal static class Problems
{
    public static IResult Refuse(int status, string code, string detail, int? retryAfter = null) =>
        Results.Json(
            Body(status, code, detail, retryAfter),
            options: (JsonSerializerOptions?)null,
            contentType: "application/problem+json",
            statusCode: status);

    public static Dictionary<string, object> Body(int status, string code, string detail, int? retryAfter = null)
    {
        var body = new Dictionary<string, object>
        {
            ["type"] = "about:blank",
            ["title"] = ReasonPhrases.GetReasonPhrase(status),
            ["status"] = status,
            ["detail"] = detail,
            ["code"] = code,
        };
        if (retryAfter is { } seconds)
        {
            body["retry_after"] = seconds;
        }

        return body;
    }

    public static IResult UnknownFlow() =>
        Refuse(StatusCodes.Status400BadRequest, "invalid_flow", "This sign-in is not valid. Start again from the application.");

    public static IResult ExpiredFlow() =>
        Refuse(StatusCodes.Status410Gone, "flow_expired", "This sign-in has expired. Start again from the application.");
}
