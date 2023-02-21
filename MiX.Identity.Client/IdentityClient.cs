using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace MiX.Identity.Client
{
	public class IdentityClient : IIdentityClient
	{
		private readonly HttpClient _client;
		private readonly string _baseAddress;
		private readonly string _clientId;
		private readonly string _clientSecret;

		public IdentityClient(string baseAddress, string clientId, string secret, HttpClientHandler httpClientHandler = null)
		{
			if (string.IsNullOrEmpty(baseAddress) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(secret))
			{
				throw new ArgumentException("Required arguments: baseAddress, clientId, secret");
			}

			_baseAddress = baseAddress;
			_clientId = clientId;
			_clientSecret = secret;

			_client = new HttpClient(httpClientHandler ?? new HttpClientHandler());
			_client.DefaultRequestHeaders.Accept.Clear();
			_client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(Constants.MEDIA_TYPE_APPLICATION_JSON));
		}


		public TokenResponse RefreshToken(string refreshToken)
		{
			return RefreshTokenAsync(refreshToken).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrEmpty(refreshToken))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			var requestData = new Dictionary<string, string>
			{
				{ Constants.IDENTITY_GRANT_TYPE, Constants.IDENTITY_REFRESH_TOKEN },
				{ Constants.IDENTITY_REFRESH_TOKEN, refreshToken}
			};

			return await GetTokenResponseAsync(requestData, cancellationToken).ConfigureAwait(false);
		}


		public TokenResponse RequestResourceOwnerPasswordToken(string username, string password, string scopes)
		{
			return RequestResourceOwnerPasswordTokenAsync(username, password, scopes).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		public async Task<TokenResponse> RequestResourceOwnerPasswordTokenAsync(string username, string password, string scopes, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: username, password, scopes");
			}

			var requestData = new Dictionary<string, string>
			{
				{ Constants.IDENTITY_GRANT_TYPE, Constants.IDENTITY_PASSWORD },
				{ Constants.IDENTITY_USERNAME, username },
				{ Constants.IDENTITY_PASSWORD, password },
				{ Constants.IDENTITY_SCOPE, scopes }
			};

			return await GetTokenResponseAsync(requestData, cancellationToken).ConfigureAwait(false);
		}


		public TokenResponse RequestClientCredentialsToken(string scopes)
		{
			return RequestClientCredentialsTokenAsync(scopes).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		public async Task<TokenResponse> RequestClientCredentialsTokenAsync(string scopes, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrEmpty(scopes))
			{
				throw new ArgumentException("Required arguments: scopes");
			}

			var requestData = new Dictionary<string, string>
			{
				{ Constants.IDENTITY_GRANT_TYPE, Constants.IDENTITY_CLIENT_CREDENTIALS },
				{ Constants.IDENTITY_SCOPE, scopes }
			};

			return await GetTokenResponseAsync(requestData, cancellationToken).ConfigureAwait(false);
		}


		private async Task<TokenResponse> GetTokenResponseAsync(IDictionary<string, string> fields, CancellationToken cancellationToken)
		{
			fields.Add(Constants.IDENTITY_CLIENT_ID, _clientId);
			fields.Add(Constants.IDENTITY_CLIENT_SECRET, _clientSecret);

			using (var request = new HttpRequestMessage(HttpMethod.Post, IDServerUrlHelper.GetTokenEndpoint(_baseAddress)){Content = new FormUrlEncodedContent(fields)})
			{
				using (var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false))
				{
					string content = null;
					if (response.Content != null)
					{
						content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
					}

					var tokenResponse = new TokenResponse(response.StatusCode, response.ReasonPhrase, content);
					if (!string.IsNullOrWhiteSpace(tokenResponse.Error))
						throw new Exception($"HttpStatusCode: {tokenResponse.HttpStatusCode}, Error: {tokenResponse.Error}");

					return tokenResponse;
				}
			}
		}
	}
}