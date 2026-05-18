package com.bbn.marti.network;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import com.bbn.marti.cot.search.model.ApiResponse;
import com.bbn.marti.remote.exception.ForbiddenException;
import com.bbn.marti.util.CommonUtil;

import tak.server.Constants;

/**
 * Admin-only onboarding and offboarding REST API.
 *
 * Endpoints:
 *   GET    /Marti/api/onboarding/users
 *     -- list users discovered from /opt/tak/UserAuthenticationFile.xml
 *
 *   POST   /Marti/api/onboarding/users
 *     -- body: {"username":"alice"}
 *        creates client cert via /opt/tak/certs/makeCert.sh, adds user to
 *        UserAuthenticationFile via UserManager certmod, returns the
 *        generated cert password ONCE in the response. The password is not
 *        persisted server-side; the admin must capture it for the operator.
 *
 *   POST   /Marti/api/onboarding/users/{username}/datapackage/{platform}
 *     -- body: {"certPass":"...", "host":"server.aevogrid.com"}
 *        builds an ATAK or iTAK mission package zip in-memory from the user's
 *        existing p12 on EFS plus the shared truststore-intermediate.p12, then
 *        streams the zip back. certPass goes into the manifest.xml so client
 *        devices can unlock the .p12.
 *
 *   DELETE /Marti/api/onboarding/users/{username}
 *     -- revokes the user's cert (CRL update), removes from UserAuthenticationFile,
 *        deletes p12/pem/key/csr/jks from EFS. The matching client_endpoint row
 *        cleanup is handled out-of-band by /clientEndPoints DELETE if needed.
 *
 * Security:
 *   - All endpoints require ROLE_ADMIN (enforced via security-context.xml
 *     intercept-url and a defensive martiUtil.isAdmin() check here).
 *   - Username validated against a tight regex; rejects anything that could
 *     traverse paths or smuggle shell metacharacters into makeCert.sh.
 *   - Cert passwords are generated with SecureRandom, returned once, never
 *     logged. The cert-pass http header on download is read directly from
 *     the request body to keep it out of access logs / referrer chains.
 *   - All actions logged with admin remote IP + target username for audit.
 */
@RestController
public class OnboardingApi extends BaseRestController {

	private static final Logger logger = LoggerFactory.getLogger(OnboardingApi.class);

	private static final Pattern SAFE_USERNAME = Pattern.compile("^[A-Za-z0-9_-]{1,32}$");
	private static final Pattern SAFE_HOST = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");
	private static final String CERTS_DIR = "/opt/tak/certs";
	private static final String CERTS_FILES_DIR = CERTS_DIR + "/files";
	private static final String TRUSTSTORE_NAME = "truststore-intermediate.p12";
	private static final String USER_AUTH_FILE = "/opt/tak/UserAuthenticationFile.xml";
	private static final String USER_MANAGER_JAR = "/opt/tak/utils/UserManager.jar";
	private static final String MAKE_CERT_SCRIPT = "makeCert.sh";

	@Autowired
	private CommonUtil martiUtil;

	private final SecureRandom random = new SecureRandom();
	// Routes audit messages to the dedicated takserver-db-audit.log appender
	// via the marker filter wired up in logback-spring.xml. Regular SLF4J
	// log calls without this marker only land in the application log.
	private static final Marker AUDIT = MarkerFactory.getMarker(Constants.AUDIT_LOG_MARKER);

	private void requireAdmin(HttpServletRequest request, String action, String targetUser) {
		String remote = request.getRemoteAddr();
		if (!martiUtil.isAdmin()) {
			String msg = "onboarding DENIED action=" + action
					+ " target=" + targetUser + " remote=" + remote;
			logger.warn(AUDIT, msg);
			throw new ForbiddenException("Admin role required");
		}
		String msg = "onboarding action=" + action
				+ " target=" + targetUser + " remote=" + remote;
		// Marker routes the entry to logs/takserver-db-audit.log via the
		// AuditLogMarkerThresholdFilter wired up in logback-spring.xml.
		// Without the marker the message only lands in the application log.
		logger.info(AUDIT, msg);
	}

	private void validateUsername(String username) {
		if (username == null || !SAFE_USERNAME.matcher(username).matches()) {
			throw new IllegalArgumentException(
					"username must match ^[A-Za-z0-9_-]{1,32}$");
		}
	}

	private void validateHost(String host) {
		if (host == null || !SAFE_HOST.matcher(host).matches()) {
			throw new IllegalArgumentException(
					"host must match ^[A-Za-z0-9.-]{1,253}$");
		}
	}

	private String generateCertPassword() {
		byte[] raw = new byte[18];
		random.nextBytes(raw);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
	}

	@GetMapping("/onboarding/users")
	public ResponseEntity<ApiResponse<List<OnboardingUser>>> listUsers(HttpServletRequest request) throws IOException {
		requireAdmin(request, "list", "*");
		// Union of two sources of truth so the panel surfaces users that
		// were created out-of-band (e.g. makeCert.sh without certmod) and
		// users that exist only as password-based admins with no .p12:
		//   1. <User identifier="..."> entries in UserAuthenticationFile.xml
		//   2. *.p12 files in /opt/tak/certs/files matching SAFE_USERNAME
		// Server/CA/truststore p12s and other infra files are filtered out.
		java.util.Map<String, OnboardingUser> byName = new java.util.LinkedHashMap<>();
		File authFile = new File(USER_AUTH_FILE);
		if (authFile.exists()) {
			String xml = new String(Files.readAllBytes(authFile.toPath()), StandardCharsets.UTF_8);
			Pattern entry = Pattern.compile("<User\\s+identifier=\"([^\"]+)\"");
			java.util.regex.Matcher m = entry.matcher(xml);
			while (m.find()) {
				String name = m.group(1);
				byName.computeIfAbsent(name, n -> new OnboardingUser(n, false))
						.inAuthFile = true;
			}
		}
		File certsDir = new File(CERTS_FILES_DIR);
		File[] p12s = certsDir.exists() ? certsDir.listFiles((dir, fn) -> fn.endsWith(".p12")) : null;
		java.util.Set<String> infraCerts = new java.util.HashSet<>(java.util.Arrays.asList(
				"intermediate-signing", "takserver", "truststore-intermediate", "truststore-root"));
		if (p12s != null) {
			for (File p12 : p12s) {
				String name = p12.getName().substring(0, p12.getName().length() - 4);
				if (infraCerts.contains(name)) continue;
				if (!SAFE_USERNAME.matcher(name).matches()) continue;
				byName.computeIfAbsent(name, n -> new OnboardingUser(n, true))
						.hasCert = true;
			}
		}
		List<OnboardingUser> users = new ArrayList<>(byName.values());
		users.sort(java.util.Comparator.comparing(u -> u.username));
		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				OnboardingUser.class.getName(), users), HttpStatus.OK);
	}

	@PostMapping("/onboarding/users")
	public ResponseEntity<ApiResponse<OnboardingResult>> createUser(
			@RequestBody CreateUserRequest body,
			HttpServletRequest request) throws Exception {
		String username = body == null ? null : body.username;
		requireAdmin(request, "create", username);
		validateUsername(username);

		if (new File(CERTS_FILES_DIR, username + ".p12").exists()) {
			throw new IllegalArgumentException("user already has a cert; revoke first");
		}

		String certPass = generateCertPassword();
		String caPass = System.getenv("CA_PASS");
		if (caPass == null || caPass.isEmpty()) {
			throw new IllegalStateException("CA_PASS env var not set on container");
		}

		ProcessBuilder makeCert = new ProcessBuilder(
				"bash", MAKE_CERT_SCRIPT, "client", username);
		makeCert.directory(new File(CERTS_DIR));
		Map<String, String> env = makeCert.environment();
		env.put("CAPASS", caPass);
		env.put("PASS", certPass);
		makeCert.redirectErrorStream(true);
		Process proc = makeCert.start();
		String makeOut = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		int makeExit = proc.waitFor();
		if (makeExit != 0) {
			logger.error("makeCert.sh failed for {} (exit={}): {}", username, makeExit, makeOut);
			throw new RuntimeException("cert generation failed; see server logs");
		}

		ProcessBuilder certmod = new ProcessBuilder(
				"java", "-jar", USER_MANAGER_JAR, "certmod", "-A",
				CERTS_FILES_DIR + "/" + username + ".pem");
		certmod.redirectErrorStream(true);
		Process cmProc = certmod.start();
		String cmOut = new String(cmProc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		int cmExit = cmProc.waitFor();
		if (cmExit != 0) {
			logger.error("certmod -A failed for {} (exit={}): {}", username, cmExit, cmOut);
			throw new RuntimeException("user registration failed; see server logs");
		}

		OnboardingResult result = new OnboardingResult(username, certPass);
		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				OnboardingResult.class.getName(), result), HttpStatus.OK);
	}

	@PostMapping("/onboarding/users/{username}/datapackage/{platform}")
	public ResponseEntity<byte[]> downloadDatapackage(
			@PathVariable("username") String username,
			@PathVariable("platform") String platform,
			@RequestBody DatapackageRequest body,
			HttpServletRequest request) throws IOException {
		requireAdmin(request, "datapackage:" + platform, username);
		validateUsername(username);
		if (!"atak".equals(platform) && !"itak".equals(platform)) {
			throw new IllegalArgumentException("platform must be atak or itak");
		}
		if (body == null || body.certPass == null || body.certPass.isEmpty()) {
			throw new IllegalArgumentException("certPass is required");
		}
		validateHost(body.host);

		File clientP12 = new File(CERTS_FILES_DIR, username + ".p12");
		File truststore = new File(CERTS_FILES_DIR, TRUSTSTORE_NAME);
		if (!clientP12.exists()) {
			throw new IllegalArgumentException("cert not found for user");
		}
		if (!truststore.exists()) {
			throw new IllegalStateException("truststore-intermediate.p12 missing on EFS");
		}

		String caPass = System.getenv("CA_PASS");
		String tsPass = caPass == null ? "atakatak" : caPass;
		byte[] clientBytes = Files.readAllBytes(clientP12.toPath());
		byte[] tsBytes = Files.readAllBytes(truststore.toPath());
		String uid = UUID.randomUUID().toString();

		ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(zipBytes)) {
			if ("atak".equals(platform)) {
				addZip(zip, "certs/" + username + ".p12", clientBytes);
				addZip(zip, "certs/" + TRUSTSTORE_NAME, tsBytes);
				addZip(zip, "prefs/atak_preferences.xml",
						atakPrefs(username, body.host, body.certPass, tsPass).getBytes(StandardCharsets.UTF_8));
				addZip(zip, "MANIFEST/manifest.xml",
						atakManifest(uid, username, body.certPass, tsPass).getBytes(StandardCharsets.UTF_8));
			} else {
				addZip(zip, username + ".p12", clientBytes);
				addZip(zip, TRUSTSTORE_NAME, tsBytes);
				addZip(zip, "preference.pref",
						itakPrefs(username, body.host, body.certPass, tsPass).getBytes(StandardCharsets.UTF_8));
				addZip(zip, "MANIFEST/manifest.xml",
						itakManifest(uid, username, body.certPass, tsPass).getBytes(StandardCharsets.UTF_8));
			}
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
		headers.setContentDispositionFormData("attachment",
				username + "-" + platform + ".zip");
		headers.setCacheControl("no-store");
		return new ResponseEntity<>(zipBytes.toByteArray(), headers, HttpStatus.OK);
	}

	@DeleteMapping("/onboarding/users/{username}")
	public ResponseEntity<ApiResponse<String>> revokeUser(
			@PathVariable("username") String username,
			HttpServletRequest request) throws Exception {
		requireAdmin(request, "revoke", username);
		validateUsername(username);

		File clientPem = new File(CERTS_FILES_DIR, username + ".pem");
		if (clientPem.exists()) {
			String caPass = System.getenv("CA_PASS");
			if (caPass != null && !caPass.isEmpty()) {
				ProcessBuilder revokeCert = new ProcessBuilder(
						"bash", "revokeCert.sh", username, "intermediate", "intermediate");
				revokeCert.directory(new File(CERTS_DIR));
				Map<String, String> env = revokeCert.environment();
				env.put("CAPASS", caPass);
				env.put("PASS", caPass);
				revokeCert.redirectErrorStream(true);
				Process p = revokeCert.start();
				p.getInputStream().readAllBytes();
				p.waitFor();
			}
			ProcessBuilder certmod = new ProcessBuilder(
					"java", "-jar", USER_MANAGER_JAR, "certmod", "-D",
					clientPem.getAbsolutePath());
			certmod.redirectErrorStream(true);
			Process cmp = certmod.start();
			cmp.getInputStream().readAllBytes();
			cmp.waitFor();
		}

		ProcessBuilder usermod = new ProcessBuilder(
				"java", "-jar", USER_MANAGER_JAR, "usermod", "-D", username);
		usermod.redirectErrorStream(true);
		Process up = usermod.start();
		up.getInputStream().readAllBytes();
		up.waitFor();

		// Clean every artifact makeCert.sh produces. The script writes the
		// primary credentials at the literal SNAME, and a -trusted variant
		// plus truststore-<sname>.p12 + config-<sname>.cfg. SNAME is the
		// raw arg, so usually matches our username case-for-case, but the
		// underlying openssl pieces sometimes leave lowercased filenames.
		// Cover both casings so an offboarded user never lingers on EFS.
		String[] casings = username.equals(username.toLowerCase())
				? new String[]{username}
				: new String[]{username, username.toLowerCase()};
		String[] suffixes = {".pem", ".key", ".csr", ".jks", ".p12", "-trusted.pem"};
		for (String cas : casings) {
			for (String ext : suffixes) {
				File f = new File(CERTS_FILES_DIR, cas + ext);
				if (f.exists() && !f.delete()) {
					logger.warn("Failed to delete {} on EFS for offboarded user",
							f.getAbsolutePath());
				}
			}
			File ts = new File(CERTS_FILES_DIR, "truststore-" + cas + ".p12");
			if (ts.exists() && !ts.delete()) {
				logger.warn("Failed to delete {} on EFS for offboarded user", ts.getAbsolutePath());
			}
			File cfg = new File(CERTS_DIR, "config-" + cas + ".cfg");
			if (cfg.exists() && !cfg.delete()) {
				logger.warn("Failed to delete {} on EFS for offboarded user", cfg.getAbsolutePath());
			}
		}

		return new ResponseEntity<>(new ApiResponse<>(Constants.API_VERSION,
				String.class.getName(), "revoked"), HttpStatus.OK);
	}

	private static void addZip(ZipOutputStream zip, String entry, byte[] data) throws IOException {
		zip.putNextEntry(new ZipEntry(entry));
		zip.write(data);
		zip.closeEntry();
	}

	private static String atakPrefs(String user, String host, String certPass, String tsPass) {
		return "<?xml version='1.0' standalone='yes'?>\n"
				+ "<preferences>\n"
				+ "  <preference version=\"1\" name=\"cot_streams\">\n"
				+ "    <entry key=\"count\" class=\"class java.lang.Integer\">1</entry>\n"
				+ "    <entry key=\"description0\" class=\"class java.lang.String\">TAK Server</entry>\n"
				+ "    <entry key=\"enabled0\" class=\"class java.lang.Boolean\">true</entry>\n"
				+ "    <entry key=\"connectString0\" class=\"class java.lang.String\">" + xmlAttr(host) + ":8089:ssl</entry>\n"
				+ "  </preference>\n"
				+ "  <preference version=\"1\" name=\"com.atakmap.app_preferences\">\n"
				+ "    <entry key=\"clientPassword\" class=\"class java.lang.String\">" + xmlAttr(certPass) + "</entry>\n"
				+ "    <entry key=\"certificateLocation\" class=\"class java.lang.String\">/cert/" + xmlAttr(user) + ".p12</entry>\n"
				+ "    <entry key=\"caPassword\" class=\"class java.lang.String\">" + xmlAttr(tsPass) + "</entry>\n"
				+ "    <entry key=\"caLocation\" class=\"class java.lang.String\">/cert/" + TRUSTSTORE_NAME + "</entry>\n"
				+ "  </preference>\n"
				+ "</preferences>\n";
	}

	private static String itakPrefs(String user, String host, String certPass, String tsPass) {
		return "<?xml version='1.0' standalone='yes'?>\n"
				+ "<preferences>\n"
				+ "  <preference version=\"1\" name=\"cot_streams\">\n"
				+ "    <entry key=\"count\" class=\"class java.lang.Integer\">1</entry>\n"
				+ "    <entry key=\"description0\" class=\"class java.lang.String\">TAK Server</entry>\n"
				+ "    <entry key=\"enabled0\" class=\"class java.lang.Boolean\">true</entry>\n"
				+ "    <entry key=\"connectString0\" class=\"class java.lang.String\">" + xmlAttr(host) + ":8089:ssl</entry>\n"
				+ "  </preference>\n"
				+ "  <preference version=\"1\" name=\"com.atakmap.app_preferences\">\n"
				+ "    <entry key=\"clientPassword\" class=\"class java.lang.String\">" + xmlAttr(certPass) + "</entry>\n"
				+ "    <entry key=\"certificateLocation\" class=\"class java.lang.String\">" + xmlAttr(user) + ".p12</entry>\n"
				+ "    <entry key=\"caPassword\" class=\"class java.lang.String\">" + xmlAttr(tsPass) + "</entry>\n"
				+ "    <entry key=\"caLocation\" class=\"class java.lang.String\">" + TRUSTSTORE_NAME + "</entry>\n"
				+ "  </preference>\n"
				+ "</preferences>\n";
	}

	private static String atakManifest(String uid, String user, String certPass, String tsPass) {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				+ "<MissionPackageManifest version=\"2\">\n"
				+ "  <Configuration>\n"
				+ "    <Parameter name=\"uid\" value=\"" + xmlAttr(uid) + "\"/>\n"
				+ "    <Parameter name=\"name\" value=\"" + xmlAttr(user) + " ATAK Connection\"/>\n"
				+ "    <Parameter name=\"onReceiveDelete\" value=\"false\"/>\n"
				+ "  </Configuration>\n"
				+ "  <Contents>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"certs/" + xmlAttr(user) + ".p12\">\n"
				+ "      <Parameter name=\"password\" value=\"" + xmlAttr(certPass) + "\"/>\n"
				+ "    </Content>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"certs/" + TRUSTSTORE_NAME + "\">\n"
				+ "      <Parameter name=\"password\" value=\"" + xmlAttr(tsPass) + "\"/>\n"
				+ "    </Content>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"prefs/atak_preferences.xml\"/>\n"
				+ "  </Contents>\n"
				+ "</MissionPackageManifest>\n";
	}

	private static String itakManifest(String uid, String user, String certPass, String tsPass) {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				+ "<MissionPackageManifest version=\"2\">\n"
				+ "  <Configuration>\n"
				+ "    <Parameter name=\"uid\" value=\"" + xmlAttr(uid) + "\"/>\n"
				+ "    <Parameter name=\"name\" value=\"" + xmlAttr(user) + " iTAK Connection\"/>\n"
				+ "    <Parameter name=\"onReceiveDelete\" value=\"false\"/>\n"
				+ "  </Configuration>\n"
				+ "  <Contents>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"" + xmlAttr(user) + ".p12\">\n"
				+ "      <Parameter name=\"password\" value=\"" + xmlAttr(certPass) + "\"/>\n"
				+ "    </Content>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"" + TRUSTSTORE_NAME + "\">\n"
				+ "      <Parameter name=\"password\" value=\"" + xmlAttr(tsPass) + "\"/>\n"
				+ "    </Content>\n"
				+ "    <Content ignore=\"false\" zipEntry=\"preference.pref\"/>\n"
				+ "  </Contents>\n"
				+ "</MissionPackageManifest>\n";
	}

	private static String xmlAttr(String v) {
		if (v == null) return "";
		return v.replace("&", "&amp;")
				.replace("<", "&lt;")
				.replace(">", "&gt;")
				.replace("\"", "&quot;")
				.replace("'", "&apos;");
	}

	public static class CreateUserRequest {
		public String username;
	}

	public static class DatapackageRequest {
		public String certPass;
		public String host;
	}

	public static class OnboardingUser {
		public String username;
		public boolean hasCert;
		public boolean inAuthFile;
		public OnboardingUser() {}
		public OnboardingUser(String username, boolean hasCert) {
			this.username = username;
			this.hasCert = hasCert;
			this.inAuthFile = false;
		}
	}

	public static class OnboardingResult {
		public String username;
		public String certPass;
		public OnboardingResult() {}
		public OnboardingResult(String username, String certPass) {
			this.username = username;
			this.certPass = certPass;
		}
	}
}
