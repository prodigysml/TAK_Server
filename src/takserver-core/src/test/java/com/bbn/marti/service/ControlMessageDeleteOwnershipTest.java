package com.bbn.marti.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * {@link SubmissionService#ownSubscriptionUidToDelete} decides which subscription a
 * t-b-a / t-b-c / t-x-c-t-r control message may delete. Subscription uids for streaming
 * clients are sequential ("tls:1", "tls:2", ...), so anything other than the sender's
 * own subscription must be refused, or one client can force-close every other
 * connection.
 *
 * The helper takes plain strings: loading the Subscription class initializes Resources,
 * which starts Ignite, so this test never touches it.
 */
public class ControlMessageDeleteOwnershipTest {

	@Test
	public void ownSubscriptionUid_isDeleted() {
		assertEquals("tls:7", SubmissionService.ownSubscriptionUidToDelete("tls:7", "tls:7"));
	}

	@Test
	public void otherSubscriptionUid_isRefused() {
		assertNull(SubmissionService.ownSubscriptionUidToDelete("tls:7", "tls:5"));
	}

	@Test
	public void clientUidAsMessageUid_isNotTreatedAsSubscriptionUid() {
		// Neither an unset clientUid (no SA yet) nor any clientUid claimed in an SA,
		// including another connection's subscription uid, grants a delete.
		assertNull(SubmissionService.ownSubscriptionUidToDelete("tls:7", "ANDROID-abc"));
	}

	@Test
	public void noOriginatingConnection_isRefused() {
		assertNull(SubmissionService.ownSubscriptionUidToDelete(null, "tls:5"));
	}

	@Test
	public void staticSubscriptionName_isRefused() {
		assertNull(SubmissionService.ownSubscriptionUidToDelete("tls:7", "myStaticSub"));
	}

	@Test
	public void emptyUids_areRefused() {
		assertNull(SubmissionService.ownSubscriptionUidToDelete("tls:7", ""));
		assertNull(SubmissionService.ownSubscriptionUidToDelete("tls:7", null));
		assertNull(SubmissionService.ownSubscriptionUidToDelete("", ""));
	}
}
