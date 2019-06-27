package com.almansa.app.authentication.authenticationprovider;

import java.security.SecureRandom;

import org.junit.Test;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.Token;

public class KeyBasedPersistenceTokenServiceTest {

	@Test
	public void test() {
		KeyBasedPersistenceTokenService tokenService = new KeyBasedPersistenceTokenService();
		tokenService.setServerSecret("SECRET21321323");
		tokenService.setServerInteger(Integer.valueOf(128));
		tokenService.setSecureRandom(new SecureRandom());
		
		Token token = tokenService.verifyToken("11");
	}
}
