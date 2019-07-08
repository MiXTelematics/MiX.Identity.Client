using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace MiX.Identity.Client
{
	public interface IIdentityClient
	{
		TokenResponse RequestResourceOwnerPasswordToken(string username, string password, string scopes);
		Task<TokenResponse> RequestResourceOwnerPasswordTokenAsync(string username, string password, string scopes);
		TokenResponse RefreshToken(string refreshToken);
		Task<TokenResponse> RefreshTokenAsync(string refreshToken);
		JwtSecurityToken DecodeToken(string token);
		TokenResponse RequestClientCredentialsToken(string scopes);
		Task<TokenResponse> RequestClientCredentialsTokenAsync(string scopes);
	}
}
