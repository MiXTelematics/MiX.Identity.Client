using System;
using System.Net;
using System.Text.Json;

namespace MiX.Identity.Client
{
	/// <summary>Represents a response to an identity server token request</summary>
	public sealed class TokenResponse
	{
		public TokenResponse(HttpStatusCode httpStatusCode, string reason, string content) : this(content)
		{
			HttpStatusCode = httpStatusCode;

			if (HttpStatusCode == HttpStatusCode.BadRequest && !string.IsNullOrEmpty(Error) && !string.IsNullOrEmpty(ErrorDescription) &&
				  Error.Equals(Constants.IDENTITY_INVALID_GRANT))
				Error = ErrorDescription;
			else if (HttpStatusCode != HttpStatusCode.OK && string.IsNullOrEmpty(Error))
				Error = reason;
		}

		private TokenResponse(string content)
		{
			if (string.IsNullOrEmpty(content))
				return;

			try
			{
				using (var jsonDoc = JsonDocument.Parse(content))
				{
					var root = jsonDoc.RootElement;
					if (root.ValueKind != JsonValueKind.Object)
						return;

					foreach (var jsonProp in root.EnumerateObject())
					{
						switch (jsonProp.Value.ValueKind)
						{
							case JsonValueKind.String:
								switch (jsonProp.Name)
								{
									case Constants.IDENTITY_ACCESS_TOKEN:
										AccessToken = jsonProp.Value.GetString();
										break;

									case Constants.IDENTITY_REFRESH_TOKEN:
										RefreshToken = jsonProp.Value.GetString();
										break;

									case Constants.IDENTITY_ERROR:
										Error = jsonProp.Value.GetString();
										break;

									case Constants.IDENTITY_ERROR_DESCRIPTION:
										ErrorDescription = jsonProp.Value.GetString();
										break;
								}
								break;

							case JsonValueKind.Number:
								switch (jsonProp.Name)
								{
									case Constants.IDENTITY_EXPIRES_IN:
										ExpiresIn = jsonProp.Value.TryGetInt32(out var val) ? val : 0;
										break;
								}
								break;
						}
					}
				}
			}
			catch (JsonException)
			{

			}
		}

		public TokenResponse(Exception ex) : this(HttpStatusCode.InternalServerError, null, null)
		{
			Error = ex.GetType().Name;
			ErrorDescription = ex.Message;
		}

		public HttpStatusCode HttpStatusCode { get; }
		public string AccessToken { get; set; }
		public int ExpiresIn { get; set; }
		public string RefreshToken { get; set; }
		public string Error { get; set; }
		public string ErrorDescription { get; set; }

	}
}
