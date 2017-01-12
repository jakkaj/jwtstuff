using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;


namespace JwtHelpers
{
    public static class JwtCreator
    {
        public static string CreateToken(ClaimsIdentity subject, string issuer, string audience, DateTime start, DateTime end, string key)
        {
            var keyConverted = Encoding.UTF8.GetString(Convert.FromBase64String(key));

            var privateSigner = new RSACryptoServiceProvider();
            privateSigner.FromXmlString(keyConverted);

            var signingCredentials = new SigningCredentials(new RsaSecurityKey(privateSigner),
                SecurityAlgorithms.RsaSha256Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = subject,
                Issuer = issuer,
                Audience = audience,
                NotBefore= start,
                Expires = end,
                SigningCredentials = signingCredentials,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return tokenString;
        }
    }
}
