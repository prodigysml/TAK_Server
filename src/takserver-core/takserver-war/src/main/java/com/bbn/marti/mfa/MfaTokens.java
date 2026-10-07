package com.bbn.marti.mfa;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Finds the OAuth access token a request authenticated with, the same places
 * AccessTokenResolver looks: the Authorization bearer header, then the
 * access_token cookie the admin login sets. The MFA stamp is keyed on it.
 */
final class MfaTokens {

	private static final String COOKIE = "access_token";
	private static final String BEARER = "Bearer ";

	private MfaTokens() {
	}

	static String accessToken(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		if (header != null && header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
			String token = header.substring(BEARER.length()).trim();
			if (!token.isEmpty()) {
				return token;
			}
		}
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie c : cookies) {
				if (COOKIE.equalsIgnoreCase(c.getName()) && c.getValue() != null && !c.getValue().isEmpty()) {
					return c.getValue();
				}
			}
		}
		return null;
	}
}
