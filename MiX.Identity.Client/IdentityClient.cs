using IdentityModel.Client;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;

namespace MiX.Identity.Client
{
	public class IdentityClient : IIdentityClient
	{
		private TokenClient _tokenClient;

		public IdentityClient(string baseAddress, string clientId, string secret) : this(baseAddress, clientId, secret, null)
		{
		}

		public IdentityClient(string baseAddress, string clientId, string secret, HttpClientHandler httpClientHandler = null)
		{
			if (String.IsNullOrEmpty(baseAddress) || String.IsNullOrEmpty(clientId) || String.IsNullOrEmpty(secret))
			{
				throw new ArgumentException("Required arguments: baseAddress, clientId, secret");
			}

			if (httpClientHandler == null) httpClientHandler = new HttpClientHandler();

			_tokenClient = new TokenClient(
					IDServerUrlHelper.GetTokenEndpoint(baseAddress),
					clientId,
					secret,
					httpClientHandler,
					AuthenticationStyle.BasicAuthentication);
		}

		public TokenResponse RequestToken(string username, string password, string scopes)
		{
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password) || String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			TokenResponse response = _tokenClient.RequestResourceOwnerPasswordAsync(username, password, scopes).ConfigureAwait(false).GetAwaiter().GetResult();
			CheckError(response);
			return response;
		}

		public async Task<TokenResponse> RequestTokenAsync(string username, string password, string scopes)
		{
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password) || String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			TokenResponse response = await _tokenClient.RequestResourceOwnerPasswordAsync(username, password, scopes).ConfigureAwait(false);
			CheckError(response);
			return response;
		}

		public TokenResponse RefreshToken(string refreshToken)
		{
			if (String.IsNullOrEmpty(refreshToken))
			{
				throw new ArgumentException("Required arguments: refreshToken");
			}

			TokenResponse response = _tokenClient.RequestRefreshTokenAsync(refreshToken).ConfigureAwait(false).GetAwaiter().GetResult();
			CheckError(response);
			return response;
		}

		public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
		{
			if (String.IsNullOrEmpty(refreshToken))
			{
				throw new ArgumentException("Required arguments: refreshToken");
			}

			TokenResponse response = await _tokenClient.RequestRefreshTokenAsync(refreshToken).ConfigureAwait(false);
			CheckError(response);
			return response;
		}

		public JwtSecurityToken DecodeToken(string token)
		{
			if (String.IsNullOrEmpty(token))
			{
				throw new ArgumentException("Required arguments: refreshToken");
			}

			return new JwtSecurityToken(token);
		}

		private void CheckError(TokenResponse response)
		{
			if (response.IsError)
			{
				throw new Exception($"HttpStatusCode: {response.HttpStatusCode}, Error: {response.Error}");
			}
		}

		public TokenResponse RequestResourceOwnerPasswordToken(string username, string password, string scopes)
		{
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password) || String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			TokenResponse response = _tokenClient.RequestResourceOwnerPasswordAsync(username, password, scopes).ConfigureAwait(false).GetAwaiter().GetResult();
			CheckError(response);
			return response;
		}

		public async Task<TokenResponse> RequestResourceOwnerPasswordTokenAsync(string username, string password, string scopes)
		{
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password) || String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			TokenResponse response = await _tokenClient.RequestResourceOwnerPasswordAsync(username, password, scopes).ConfigureAwait(false);
			CheckError(response);
			return response;
		}

		public TokenResponse RequestClientCredentialsToken(string scopes)
		{
			if (String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: scopes");
			}

			TokenResponse response = _tokenClient.RequestClientCredentialsAsync(scopes).ConfigureAwait(false).GetAwaiter().GetResult();
			CheckError(response);
			return response;
		}

		public async Task<TokenResponse> RequestClientCredentialsTokenAsync(string scopes)
		{
			if (String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: scopes");
			}

			TokenResponse response = await _tokenClient.RequestClientCredentialsAsync(scopes).ConfigureAwait(false);
			CheckError(response);
			return response;
		}

	}
}