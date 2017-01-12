using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using SecurityToken = System.IdentityModel.Tokens.SecurityToken;
using SecurityTokenValidationException = System.IdentityModel.Tokens.SecurityTokenValidationException;


namespace JwtHelpers
{
    public static class Validator
    {
        public static TokenResult ValidateWithRsaKey(string token, string publicKey, string issuer, string audience)
        {
            var keyExtracted = Encoding.UTF8.GetString(Convert.FromBase64String(publicKey));

            var publicOnly = new RSACryptoServiceProvider();
            publicOnly.FromXmlString(keyExtracted);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(publicOnly),
                ValidIssuer = issuer,
                ValidateIssuer = true,
                ValidAudience = audience,
                AudienceValidator =
                    (audiences, securityToken, parameters) =>
                        parameters.ValidAudience == null || audiences.Contains(parameters.ValidAudience)
            };
            return Validate(token, validationParameters);
        }

        public static TokenResult Validate(string token, TokenValidationParameters validationParameters)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            string failReason = null;

            var tokenResult = new TokenResult();

            try
            {
                Microsoft.IdentityModel.Tokens.SecurityToken validated = null;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validated);

                if (principal != null)
                {
                    tokenResult.Claims = _getClaims(principal);
                    tokenResult.IsValid = true;
                }
            }
            catch (SecurityTokenValidationException ex)
            {
                failReason = $"SecurityTokenValidationException: {ex.Message}";
            }
            catch (ArgumentException ex)
            {
                failReason = $"ArgumentException: {ex.Message}";
            }
            catch (Exception ex)
            {
                failReason = $"Exception: {ex.Message}";
            }

            if (failReason == null) return tokenResult;

            tokenResult.IsValid = false;
            tokenResult.FailReason = failReason;

            return tokenResult;
        }

        static Dictionary<string, string> _getClaims(ClaimsPrincipal principal)
        {
            var dict = new Dictionary<string, string>();
            foreach (var c in principal.Claims.Where(c => !dict.ContainsKey(c.Type)))
            {
                dict.Add(c.Type, c.Value);
            }

            return dict;
        }
    }
}
