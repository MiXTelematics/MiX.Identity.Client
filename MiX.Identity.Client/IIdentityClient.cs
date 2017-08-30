using System;
using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;

namespace MiX.Identity.Client
{
	public interface IIdentityClient
	{
		TokenResponse RequestToken(string username, string password, string scopes);
		TokenResponse RefreshToken(string refreshToken);
		JwtSecurityToken DecodeToken(string token);
	}
}
