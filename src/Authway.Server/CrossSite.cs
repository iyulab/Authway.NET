namespace Authway.Server;

/// <summary>
/// The flow API changes things for the person whose browser calls it — it signs them in, out, or
/// allows an application in. A flow id is a secret, which is most of the defence; this is the rest:
/// a request that the browser itself marks as coming from another site is not the sign-in screen
/// asking, whatever it carries. Calls that are not from a browser carry no such mark and are not affected.
/// </summary>
internal static class CrossSite
{
    public static RouteHandlerBuilder RefuseCrossSite(this RouteHandlerBuilder endpoint) =>
        endpoint.AddEndpointFilter(async (context, next) =>
        {
            if (string.Equals(context.HttpContext.Request.Headers["Sec-Fetch-Site"], "cross-site", StringComparison.OrdinalIgnoreCase))
            {
                return Problems.Refuse(StatusCodes.Status403Forbidden, "forbidden", "This request did not come from the sign-in screen.");
            }

            return await next(context);
        });
}
