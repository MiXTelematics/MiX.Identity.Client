using System;
using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;

namespace MiX.Identity.Client
{
	public class IdentityClient : IIdentityClient
	{
		private TokenClient _tokenClient;

		public IdentityClient(string baseAddress, string clientId, string secret)
		{
			if (String.IsNullOrEmpty(baseAddress) || String.IsNullOrEmpty(clientId) || String.IsNullOrEmpty(secret))
			{
				throw new ArgumentException("Required arguments: baseAddress, clientId, secret");
			}

			_tokenClient = new TokenClient(
					IDServerUrlHelper.GetTokenEndpoint(baseAddress),
					clientId,
					secret);
		}
		public TokenResponse RequestToken(string username, string password, string scopes)
		{
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password) || String.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			TokenResponse reponse = _tokenClient.RequestResourceOwnerPasswordAsync(username, password, scopes).Result;
			CheckError(reponse);
			return reponse;
		}

		public TokenResponse RefreshToken(string refreshToken)
		{
			if (String.IsNullOrEmpty(refreshToken))
			{
				throw new ArgumentException("Required arguments: refreshToken");
			}

			TokenResponse reponse = _tokenClient.RequestRefreshTokenAsync(refreshToken).Result;
			CheckError(reponse);
			return reponse;
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

	}
}