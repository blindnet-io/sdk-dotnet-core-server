using Blindnet.Utils;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;

namespace Blindnet
{
    /// <summary>
    /// Service that is responsible for creating and validating JWT
    /// </summary>
    public class TokenService
    {
        private readonly string _appID;
        private readonly Ed25519PrivateKeyParameters _privateKey;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="applicationId">Application ID</param>
        /// <param name="clientPrivateKey">Application private key</param>
        public TokenService(string applicationId, string clientPrivateKey)
        {
            _appID = applicationId;
            var privateKeyBytes = Base64UrlEncoder.DecodeBytes(clientPrivateKey);
            Stream privateStream = new MemoryStream(privateKeyBytes);
            _privateKey = new Ed25519PrivateKeyParameters(privateStream);
        }

        /// <summary>
        /// Generate temporary user token
        /// </summary>
        /// <param name="groupId">Group ID</param>
        /// <param name="userIds">Comma separated user IDs</param>
        /// <returns>Jwt token string</returns>
        public string GenerateTempUserToken(string groupId, string userIds)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            if (!string.IsNullOrEmpty(groupId))
            {
                claims.Add(new Claim(AppSettings.TokenUserGroupIDParamName, groupId));
            }

            if (!string.IsNullOrEmpty(userIds))
            {
                claims.Add(new Claim(AppSettings.TokenUserIDsListParamName, userIds));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                TokenType = AppSettings.ShortTokenName,
                Subject = new ClaimsIdentity(claims.ToArray()),
                Expires = DateTime.Now.ToUniversalTime().AddMinutes(30),
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(_privateKey), ExtendedSecurityAlgorithms.EdDsa)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }

        /// <summary>
        /// Generate user token
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="groupId">Group ID</param>
        /// <returns>Jwt token string</returns>
        public string GenerateUserToken(string userId, string groupId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            if (!string.IsNullOrEmpty(userId))
            {
                claims.Add(new Claim(AppSettings.TokenUserIDParamName, userId));
            }

            if (!string.IsNullOrEmpty(groupId))
            {
                claims.Add(new Claim(AppSettings.TokenUserGroupIDParamName, groupId));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                TokenType = AppSettings.RegularTokenName,
                Subject = new ClaimsIdentity(claims.ToArray()),
                Expires = DateTime.Now.ToUniversalTime().AddHours(12),
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(_privateKey), ExtendedSecurityAlgorithms.EdDsa)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
        
        /// <summary>
        /// Generate client token
        /// </summary>
        /// <returns>Jwt token string</returns>
        public string GenerateClientToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                TokenType = AppSettings.ClientTokenName,
                Subject = new ClaimsIdentity(claims.ToArray()),
                Expires = DateTime.Now.ToUniversalTime().AddDays(1),
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(_privateKey), ExtendedSecurityAlgorithms.EdDsa)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
    }
}
