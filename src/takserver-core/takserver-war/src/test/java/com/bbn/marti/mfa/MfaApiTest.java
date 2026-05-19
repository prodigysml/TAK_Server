package com.bbn.marti.mfa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.bbn.marti.cot.search.model.ApiResponse;

/**
 * Direct unit tests for {@link MfaApi}. We bypass MockMvc on purpose —
 * the API only depends on MfaService and the request principal, so a
 * direct method call gives full coverage without standing up the
 * Spring/Tomcat machinery.
 */
public class MfaApiTest {

	private MfaService mfaService;
	private LoginAttemptService attempts;
	private MfaApi api;
	private HttpServletRequest request;
	private HttpSession session;

	@Before
	public void setUp() {
		mfaService = mock(MfaService.class);
		attempts = new LoginAttemptService();
		api = new MfaApi(mfaService, attempts);
		request = mock(HttpServletRequest.class);
		session = mock(HttpSession.class);
		Principal principal = mock(Principal.class);
		when(principal.getName()).thenReturn("alice");
		when(request.getUserPrincipal()).thenReturn(principal);
		when(request.getRemoteAddr()).thenReturn("127.0.0.1");
		when(request.getSession(true)).thenReturn(session);
	}

	@Test(expected = IllegalStateException.class)
	public void startEnrollRejectsAnonymous() {
		when(request.getUserPrincipal()).thenReturn(null);
		api.startEnroll(request);
	}

	@Test
	public void startEnrollReturnsSecretWhenUnenrolled() {
		MfaService.MfaRow row = newRow("alice", "JBSWY3DPEHPK3PXP", false);
		when(mfaService.getOrProvision("alice")).thenReturn(row);

		ResponseEntity<ApiResponse<MfaApi.EnrollResponse>> resp = api.startEnroll(request);

		assertEquals(HttpStatus.OK, resp.getStatusCode());
		MfaApi.EnrollResponse body = resp.getBody().getData();
		assertEquals("alice", body.username);
		assertEquals(false, body.enrolled);
		assertEquals("JBSWY3DPEHPK3PXP", body.secretB32);
		assertNotNull("otpauth URI must be generated", body.otpAuthUri);
	}

	@Test
	public void startEnrollHidesSecretWhenAlreadyEnrolled() {
		MfaService.MfaRow row = newRow("alice", "JBSWY3DPEHPK3PXP", true);
		when(mfaService.getOrProvision("alice")).thenReturn(row);

		MfaApi.EnrollResponse body = api.startEnroll(request).getBody().getData();
		assertEquals(true, body.enrolled);
		assertNull("must not leak secret to already-enrolled user", body.secretB32);
		assertNull(body.otpAuthUri);
	}

	@Test
	public void finishEnrollRejectsInvalidCode() {
		String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // RFC test secret
		MfaService.MfaRow row = newRow("alice", secret, false);
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));

		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = "000000"; // wrong

		ResponseEntity<ApiResponse<String>> resp = api.finishEnroll(body, request);
		assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
		verify(mfaService, times(0)).markEnrolled("alice");
	}

	@Test
	public void finishEnrollAcceptsValidCodeAndStampsSession() {
		String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		MfaService.MfaRow row = newRow("alice", secret, false);
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));

		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = TotpUtil.generateCode(secret, System.currentTimeMillis() / 1000L);

		ResponseEntity<ApiResponse<String>> resp = api.finishEnroll(body, request);
		assertEquals(HttpStatus.OK, resp.getStatusCode());
		verify(mfaService).markEnrolled("alice");
		verify(session).setAttribute(MfaApi.SESSION_MFA_VERIFIED, Boolean.TRUE);
	}

	@Test(expected = IllegalStateException.class)
	public void finishEnrollFailsWhenNoRow() {
		when(mfaService.findByUsername("alice")).thenReturn(Optional.empty());
		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = "123456";
		api.finishEnroll(body, request);
	}

	@Test
	public void verifyRejectsInvalidCode() {
		String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		MfaService.MfaRow row = newRow("alice", secret, true);
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));

		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = "000000";

		ResponseEntity<ApiResponse<String>> resp = api.verify(body, request);
		assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
		verify(session, times(0)).setAttribute(MfaApi.SESSION_MFA_VERIFIED, Boolean.TRUE);
	}

	@Test
	public void verifyAcceptsValidCode() {
		String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
		MfaService.MfaRow row = newRow("alice", secret, true);
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));

		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = TotpUtil.generateCode(secret, System.currentTimeMillis() / 1000L);

		ResponseEntity<ApiResponse<String>> resp = api.verify(body, request);
		assertEquals(HttpStatus.OK, resp.getStatusCode());
		verify(session).setAttribute(MfaApi.SESSION_MFA_VERIFIED, Boolean.TRUE);
		verify(mfaService).touchLastUsed("alice");
	}

	@Test(expected = IllegalStateException.class)
	public void verifyRejectsUnenrolledUser() {
		MfaService.MfaRow row = newRow("alice", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", false);
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));

		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = "123456";
		api.verify(body, request);
	}

	@Test(expected = IllegalStateException.class)
	public void verifyRejectsMissingRow() {
		when(mfaService.findByUsername("alice")).thenReturn(Optional.empty());
		MfaApi.CodeRequest body = new MfaApi.CodeRequest();
		body.code = "123456";
		api.verify(body, request);
	}

	private static MfaService.MfaRow newRow(String user, String secretB32, boolean enrolled) {
		MfaService.MfaRow r = new MfaService.MfaRow();
		r.username = user;
		r.secretB32 = secretB32;
		r.enrolled = enrolled;
		return r;
	}
}
