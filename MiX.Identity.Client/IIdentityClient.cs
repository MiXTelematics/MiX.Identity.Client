using IdentityModel.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace MiX.Identity.Client
{
	public interface IIdentityClient
	{
		[Obsolete("RequestToken is deprecated, please use RequestResourceOwnerPasswordToken instead.")]
		TokenResponse RequestToken(string username, string password, string scopes);
		[Obsolete("RequestTokenAsync is deprecated, please use RequestResourceOwnerPasswordTokenAsync instead.")]
		Task<TokenResponse> RequestTokenAsync(string username, string password, string scopes);
		TokenResponse RefreshToken(string refreshToken);
		Task<TokenResponse> RefreshTokenAsync(string refreshToken);
		JwtSecurityToken DecodeToken(string token);
		TokenResponse RequestResourceOwnerPasswordToken(string username, string password, string scopes);
		Task<TokenResponse> RequestResourceOwnerPasswordTokenAsync(string username, string password, string scopes);
		TokenResponse RequestClientCredentialsToken(string scopes);
		Task<TokenResponse> RequestClientCredentialsTokenAsync(string scopes);
	}
}
