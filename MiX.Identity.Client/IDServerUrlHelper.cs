namespace MiX.Identity.Client
{
	public static class IDServerUrlHelper
	{
		public static string GetAuthorizeEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/authorize";
		}
		public static string GetLogoutEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/endsession";
		}
		public static string GetTokenEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/token";
		}
		public static string GetUserInfoEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/userinfo";
		}
		public static string GetIdentityTokenValidationEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/identitytokenvalidation";
		}
		public static string GetTokenRevocationEndpoint(string baseAddress)
		{
			return baseAddress + "/connect/revocation";
		}
	}
}
