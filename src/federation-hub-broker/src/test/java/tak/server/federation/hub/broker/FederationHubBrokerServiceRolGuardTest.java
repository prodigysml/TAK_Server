package tak.server.federation.hub.broker;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Verifies the ROL size guard added to parseRol. The federation broker
 * receives ROL programs from TLS-authenticated federate peers, but the
 * server itself must remain self-protecting against a misbehaving or
 * compromised peer attempting to drive unbounded ANTLR parse work
 * (CWE-400, CWE-770).
 */
public class FederationHubBrokerServiceRolGuardTest {

	@Test
	public void rejectsNullProgram() {
		assertTrue(FederationHubBrokerService.shouldRejectRolProgram(null, 100));
	}

	@Test
	public void acceptsEmptyProgram() {
		assertFalse(FederationHubBrokerService.shouldRejectRolProgram("", 100));
	}

	@Test
	public void acceptsProgramAtCap() {
		String program = "a".repeat(100);
		assertFalse(FederationHubBrokerService.shouldRejectRolProgram(program, 100));
	}

	@Test
	public void rejectsProgramOneByteOverCap() {
		String program = "a".repeat(101);
		assertTrue(FederationHubBrokerService.shouldRejectRolProgram(program, 100));
	}

	@Test
	public void rejectsHugeProgram() {
		String program = "x".repeat(10_000_000);
		assertTrue(FederationHubBrokerService.shouldRejectRolProgram(program, 65_536));
	}

	@Test
	public void defaultCapIsReasonable() {
		// Sanity-check the default isn't tiny (would break legit traffic)
		// or extreme (would defeat the guard).
		assertTrue(FederationHubBrokerService.MAX_ROL_PROGRAM_BYTES >= 4_096);
		assertTrue(FederationHubBrokerService.MAX_ROL_PROGRAM_BYTES <= 1_048_576);
	}
}
