using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace MiX.Identity.Client
{
	public interface IIdentityClient
	{
		TokenResponse RequestToken(string username, string password, string scopes);
		Task<TokenResponse> RequestTokenAsync(string username, string password, string scopes);
		TokenResponse RefreshToken(string refreshToken);
		Task<TokenResponse> RefreshTokenAsync(string refreshToken);
		JwtSecurityToken DecodeToken(string token);
	}
}
