using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Authway.Server;

/// <summary>
/// Writes the audience of an access token as a list, as the contract's <c>aud</c> is, even when it names one
/// resource server: a lone audience is otherwise written as a string, and a resource server reading <c>aud</c> as
/// a list would have to guess. ID tokens are left as they are (their audience is the application).
/// </summary>
internal sealed class AudienceAsListTokenHandler : JsonWebTokenHandler
{
    private const string AccessTokenType = "at+jwt";

    public AudienceAsListTokenHandler() => SetDefaultTimesOnTokenCreation = false;

    public override string CreateToken(SecurityTokenDescriptor tokenDescriptor)
    {
        ArgumentNullException.ThrowIfNull(tokenDescriptor);
        if (tokenDescriptor.TokenType == AccessTokenType)
        {
            if (!string.IsNullOrEmpty(tokenDescriptor.Audience))
            {
                tokenDescriptor.Claims ??= new Dictionary<string, object>();
                tokenDescriptor.Claims["aud"] = new[] { tokenDescriptor.Audience };
                tokenDescriptor.Audience = null;
            }
            else if (tokenDescriptor.Claims is not null && tokenDescriptor.Claims.TryGetValue("aud", out var audience) && audience is string single)
            {
                tokenDescriptor.Claims["aud"] = new[] { single };
            }
        }

        return base.CreateToken(tokenDescriptor);
    }
}
