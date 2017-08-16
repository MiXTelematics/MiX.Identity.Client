using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Linq;
using Shouldly;

namespace MiX.Identity.Client.Tests.IntegrationTests
{
	[TestClass]
	public class IntTests_IdentityClient
	{
		private static IdentityClient _client;
		// Dev settings
		private static string username = "rootuser@mixtel.com";
		private static string password = "dynamix_is_awesome";
		private static string scopes = "offline_access MiX.Integrate";  // offline_access is required to refresh tokens
		private static string accountId = "40000000010001";
		private static string identityServerBaseAddress = "http://localhost/MiX.Authentication.Identity/core";
		private static string clientId = "mix.identity.ro.client";
		private static string secret = "MixT3l3m@tics";

		[ClassInitialize()]
		public static void ClassInit(TestContext context)
		{
			_client = new IdentityClient(identityServerBaseAddress, clientId, secret);
		}

		[ClassCleanup()]
		public static void ClassCleanup()
		{

		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_GetAccessTokenRefresh()
		{
			// Arrange

			// Act
			TokenResponse resp = _client.RequestToken(username, password, scopes);
			JwtSecurityToken data1 = _client.DecodeToken(resp.AccessToken);
			TokenResponse respRefresh = _client.RefreshToken(resp.RefreshToken);
			JwtSecurityToken data2 = _client.DecodeToken(respRefresh.AccessToken);

			// Assert
			Assert.IsTrue(!string.IsNullOrEmpty(resp.AccessToken));
			Assert.IsTrue(!string.IsNullOrEmpty(respRefresh.AccessToken));
			Assert.IsTrue(data2.Subject == accountId);

			//Act
			Claim claimEmail = data1.Claims.FirstOrDefault(f => f.Type.Equals("Email"));
			Claim claimFullName = data1.Claims.FirstOrDefault(f => f.Type.Equals("FullName"));
			Claim claimAccountId = data1.Claims.FirstOrDefault(f => f.Type.Equals("AccountId"));
			Claim claimUserName = data1.Claims.FirstOrDefault(f => f.Type.Equals("UserName"));
			Claim claimOrganisationGroupId = data1.Claims.FirstOrDefault(f => f.Type.Equals("OrganisationGroupId"));
			Claim claimThrottlingSize = data1.Claims.FirstOrDefault(f => f.Type.Equals("ThrottlingSize"));
			Claim claimAuthProvider = data1.Claims.FirstOrDefault(f => f.Type.Equals("AuthProvider"));
			Claim claimAuthToken = data1.Claims.FirstOrDefault(f => f.Type.Equals("AuthToken"));

			//Assert 
			claimEmail.ShouldNotBeNull();
			claimFullName.ShouldNotBeNull();
			claimAccountId.ShouldNotBeNull();
			claimUserName.ShouldNotBeNull();
			claimOrganisationGroupId.ShouldNotBeNull();
			claimThrottlingSize.ShouldNotBeNull();
			claimAuthProvider.ShouldNotBeNull();
			claimAuthToken.ShouldNotBeNull();

			claimEmail.Value.ShouldNotBe("");
			claimFullName.Value.ShouldNotBe("");
			claimAccountId.Value.ShouldNotBe("");
			claimUserName.Value.ShouldNotBe("");
			claimOrganisationGroupId.Value.ShouldNotBe("");
			claimThrottlingSize.Value.ShouldNotBe("");
			claimAuthProvider.Value.ShouldNotBe("");
			claimAuthToken.Value.ShouldNotBe("");
		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_InvalidConstructorArguments()
		{
			// Arrange    

			// Act  
			ArgumentException ex = Should.Throw<ArgumentException>(() =>
			{
				IdentityClient client = new IdentityClient("", "", "");
			});

			// Assert
			ex.ShouldNotBeNull();
			ex.Message.Length.ShouldBePositive();
		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_InvalidRequestTokenArguments()
		{
			// Arrange    

			// Act  
			ArgumentException ex = Should.Throw<ArgumentException>(() =>
			{
				TokenResponse resp = _client.RequestToken("", "", "");
			});

			// Assert
			ex.ShouldNotBeNull();
			ex.Message.ShouldNotBe("");
		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_InvalidDecodeTokenArguments()
		{
			// Arrange    

			// Act  
			ArgumentException ex = Should.Throw<ArgumentException>(() =>
			{
				JwtSecurityToken data1 = _client.DecodeToken("");
			});

			// Assert
			ex.ShouldNotBeNull();
			ex.Message.ShouldNotBe("");
		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_InvalidRefreshTokenArguments()
		{
			// Arrange    

			// Act  
			ArgumentException ex = Should.Throw<ArgumentException>(() =>
			{
				TokenResponse respRefresh = _client.RefreshToken("");
			});

			// Assert
			ex.ShouldNotBeNull();
			ex.Message.ShouldNotBe("");
		}

		[TestMethod, TestCategory("Integration")]
		public void IntTests_Client_IdentityClient_InvalidRefreshToken()
		{
			// Arrange    

			// Act  
			Exception ex = Should.Throw<Exception>(() =>
			{
				TokenResponse respRefresh = _client.RefreshToken("bad token");
			});

			// Assert
			ex.ShouldNotBeNull();
			ex.Message.ShouldNotBe("");
		}

	}
}
