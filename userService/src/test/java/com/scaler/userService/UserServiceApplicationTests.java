package com.scaler.userService;

import com.scaler.userService.security.Repository.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@SpringBootTest
class UserServiceApplicationTests {

	@Autowired
	private JpaRegisteredClientRepository jpaRegisteredClientRepository;

	@Test
	void contextLoads() {
	}
	//@Test
//	void testFindClient() {
//		RegisteredClient client = jpaRegisteredClientRepository.findByClientId("my-client-id");
//		System.out.println(client);
//	}

//	@Test
//	void storeARegisteredClientInDb() {
//		if (jpaRegisteredClientRepository.findByClientId("productService") == null) {
//
//			RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
//					.clientId("productService")
//					.clientSecret("password")  // No encoding, or use bCryptPasswordEncoder.encode("password")
//					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//					.redirectUri("https://oauth.pstmn.io/v1/callback")
//					.postLogoutRedirectUri("http://127.0.0.1:8080/")
//					.scope(OidcScopes.OPENID)
//					.scope(OidcScopes.PROFILE)
//					.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
//					.build();
//
//			jpaRegisteredClientRepository.save(client);
//		}

	}

