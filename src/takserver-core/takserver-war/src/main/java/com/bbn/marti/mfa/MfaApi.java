package com.bbn.marti.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbn.marti.cot.search.model.ApiResponse;
import com.bbn.marti.network.BaseRestController;

import tak.server.Constants;

/**
 * MFA endpoints called by the enroll/verify HTML pages. The current
 * authenticated principal (from the existing password login) is the
 * username key — the API never accepts a username from the client so a
 * compromised session cannot enrol or verify on behalf of another user.
 *
 *   GET  /Marti/api/mfa/enroll
 *     - If the user is already enrolled, returns {enrolled:true} so the
 *       page can redirect to verify instead of re-showing a QR code.
 *     - Otherwise provisions (or returns) a pending secret and returns the
 *       base32 secret + otpauth:// URI for the QR.
 *
 *   POST /Marti/api/mfa/enroll  body: {code:"123456"}
 *     - Verifies the code against the pending secret, flips enrolled=true,
 *       and stamps the session as mfa_verified so the gate filter lets the
 *       admin through to the rest of /Marti.
 *
 *   POST /Marti/api/mfa/verify  body: {code:"123456"}
 *     - For already-enrolled users at session start. Stamps mfa_verified.
 *
 * Reset is intentionally absent here — only the operator CLI can clear a
 * user's secret. See Taskfile.yml mfa-reset.
 */
@RestController
public class MfaApi extends BaseRestController {

	private static final Logger logger = LoggerFactory.getLogger(MfaApi.class);
	private static final Marker AUDIT = MarkerFactory.getMarker(Constants.AUDIT_LOG_MARKER);

	/** Session attribute the gate filter consults; set true after a fresh code. */
	public static final String SESSION_MFA_VERIFIED = "mfa_verified";

	@Autowired
	private MfaService mfaService;

	private String currentUsername(HttpServletRequest request) {
		if (request.getUserPrincipal() == null || request.getUserPrincipal().getName() == null) {
			throw new IllegalStateException("no authenticated principal");
		}
		return request.getUserPrincipal().getName();
	}

	@GetMapping("/mfa/enroll")
	public ResponseEntity<ApiResponse<EnrollResponse>> startEnroll(HttpServletRequest request) {
		String user = currentUsername(request);
		MfaService.MfaRow row = mfaService.getOrProvision(user);
		EnrollResponse resp = new EnrollResponse();
		resp.username = user;
		resp.enrolled = row.enrolled;
		if (!row.enrolled) {
			resp.secretB32 = row.secretB32;
			resp.otpAuthUri = TotpUtil.otpAuthUri("TAK Server", user, row.secretB32);
		}
		logger.info(AUDIT, "mfa start-enroll user={} alreadyEnrolled={} remote={}",
				user, row.enrolled, request.getRemoteAddr());
		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				EnrollResponse.class.getName(), resp), HttpStatus.OK);
	}

	@PostMapping("/mfa/enroll")
	public ResponseEntity<ApiResponse<String>> finishEnroll(
			@RequestBody CodeRequest body, HttpServletRequest request) {
		String user = currentUsername(request);
		MfaService.MfaRow row = mfaService.findByUsername(user)
				.orElseThrow(() -> new IllegalStateException("enroll not started"));
		if (row.enrolled) {
			// Already enrolled — treat as verify path so a stale enroll page
			// can still complete the session.
			return verifyCommon(user, body, request, "finishEnroll(already-enrolled)");
		}
		if (!TotpUtil.verify(row.secretB32, body == null ? null : body.code)) {
			logger.warn(AUDIT, "mfa enroll-FAIL user={} remote={}",
					user, request.getRemoteAddr());
			return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
					String.class.getName(), "invalid code"), HttpStatus.UNAUTHORIZED);
		}
		mfaService.markEnrolled(user);
		HttpSession session = request.getSession(true);
		session.setAttribute(SESSION_MFA_VERIFIED, Boolean.TRUE);
		logger.info(AUDIT, "mfa enroll-OK user={} remote={}", user, request.getRemoteAddr());
		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				String.class.getName(), "enrolled"), HttpStatus.OK);
	}

	@PostMapping("/mfa/verify")
	public ResponseEntity<ApiResponse<String>> verify(
			@RequestBody CodeRequest body, HttpServletRequest request) {
		String user = currentUsername(request);
		return verifyCommon(user, body, request, "verify");
	}

	private ResponseEntity<ApiResponse<String>> verifyCommon(
			String user, CodeRequest body, HttpServletRequest request, String action) {
		MfaService.MfaRow row = mfaService.findByUsername(user)
				.orElseThrow(() -> new IllegalStateException("user not enrolled"));
		if (!row.enrolled) {
			throw new IllegalStateException("user not enrolled");
		}
		if (!TotpUtil.verify(row.secretB32, body == null ? null : body.code)) {
			logger.warn(AUDIT, "mfa {}-FAIL user={} remote={}",
					action, user, request.getRemoteAddr());
			return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
					String.class.getName(), "invalid code"), HttpStatus.UNAUTHORIZED);
		}
		mfaService.touchLastUsed(user);
		HttpSession session = request.getSession(true);
		session.setAttribute(SESSION_MFA_VERIFIED, Boolean.TRUE);
		logger.info(AUDIT, "mfa {}-OK user={} remote={}",
				action, user, request.getRemoteAddr());
		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				String.class.getName(), "verified"), HttpStatus.OK);
	}

	public static class CodeRequest {
		public String code;
	}

	public static class EnrollResponse {
		public String username;
		public boolean enrolled;
		public String secretB32;
		public String otpAuthUri;
	}
}
