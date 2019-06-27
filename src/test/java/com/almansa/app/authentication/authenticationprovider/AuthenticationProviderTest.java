package com.almansa.app.authentication.authenticationprovider;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AuthenticationProviderTest {

	private PasswordEncoder noOpPasswordEncoder;

	@Before
	public void init() {
		noOpPasswordEncoder = new PasswordEncoder() {

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return encode(rawPassword).equals(encodedPassword);
			}

			@Override
			public String encode(CharSequence rawPassword) {
				return rawPassword.toString();
			}
		};
	}

	@Test(expected = InternalAuthenticationServiceException.class)
	public void DaoAuthenticationProvider의_사용을_위해선_반드시_userDetailService가_포함되어야_한다() {
		AuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();
		AuthenticationManager authManager = new ProviderManager(Arrays.asList(daoAuthProvider));

		authManager.authenticate(new UsernamePasswordAuthenticationToken("skennel", "1111"));
	}

	@Test
	public void userNameDetailService를_이용한_인증() {
		DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();

		// 오직 하나의 User만 리턴하는 Mock UserDetailService
		daoAuthProvider.setUserDetailsService((userName) -> {
			return new User("skennel", "1111", Arrays.asList(new SimpleGrantedAuthority("admin")));
		});

		// 아무것도 안하는 PasswordEncoder 세팅
		daoAuthProvider.setPasswordEncoder(noOpPasswordEncoder);

		AuthenticationManager authManager = new ProviderManager(Arrays.asList(daoAuthProvider));

		Authentication authResultSuccess = authManager
				.authenticate(new UsernamePasswordAuthenticationToken("skennel", "1111"));
		assertEquals(true, authResultSuccess.isAuthenticated());
		assertEquals("skennel", authResultSuccess.getName());
	}

	@Test(expected = BadCredentialsException.class)
	public void userNameDetailService를_이용한_인증_인증실패테스트() {
		DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();

		daoAuthProvider.setUserDetailsService((userName) -> {
			return new User("skennel", "1111", Arrays.asList(new SimpleGrantedAuthority("admin")));
		});

		daoAuthProvider.setPasswordEncoder(noOpPasswordEncoder);

		AuthenticationManager authManager = new ProviderManager(Arrays.asList(daoAuthProvider));

		authManager.authenticate(new UsernamePasswordAuthenticationToken("gaeko14", "2222"));
	}

	@Test
	public void AuthenticationProvider_체이닝() {
		DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();

		daoAuthProvider.setUserDetailsService((userName) -> {
			return new User("skennel", "1111", Arrays.asList(new SimpleGrantedAuthority("admin")));
		});

		daoAuthProvider.setPasswordEncoder(noOpPasswordEncoder);

		RememberMeAuthenticationProvider rememberMeAuthProvider = new RememberMeAuthenticationProvider("secret_key");

		AuthenticationManager authManager = new ProviderManager(Arrays.asList(daoAuthProvider, rememberMeAuthProvider));

		Authentication authResultDao = authManager
				.authenticate(new UsernamePasswordAuthenticationToken("skennel", "1111"));
		Authentication authResultRemember = authManager.authenticate(new RememberMeAuthenticationToken("secret_key",
				"1111", Arrays.asList(new SimpleGrantedAuthority("admin"))));
	
	}
}
