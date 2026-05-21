package com.bbn.marti.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;

import org.junit.Test;

/**
 * Unit tests for SubmissionService.isPublishTargetBlocked — verifies SSRF
 * mitigation on the outbound-publish path (CWE-918). Original code accepted
 * any host/port from attacker XML and opened a connection to it.
 */
public class SubmissionServiceSsrfTest {

	private static InetAddress addr(String host) throws Exception {
		return InetAddress.getByName(host);
	}

	@Test
	public void blocksLoopbackV4() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("127.0.0.1"), 8080, "127.0.0.1", "");
		assertNotNull("must block loopback", r);
		assertTrue(r.toLowerCase().contains("loopback") || r.toLowerCase().contains("private"));
	}

	@Test
	public void blocksLoopbackV6() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("::1"), 8080, "::1", "");
		assertNotNull(r);
	}

	@Test
	public void blocksAnyLocal() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("0.0.0.0"), 8080, "0.0.0.0", "");
		assertNotNull(r);
	}

	@Test
	public void blocksPrivate10() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("10.0.0.5"), 8080, "10.0.0.5", "");
		assertNotNull("must block RFC1918 10/8", r);
	}

	@Test
	public void blocksPrivate172_16() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("172.16.5.5"), 8080, "172.16.5.5", "");
		assertNotNull("must block RFC1918 172.16/12", r);
	}

	@Test
	public void blocksPrivate192_168() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("192.168.1.1"), 8080, "192.168.1.1", "");
		assertNotNull("must block RFC1918 192.168/16", r);
	}

	@Test
	public void blocksLinkLocal169_254() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("169.254.169.254"), 8080, "169.254.169.254", "");
		assertNotNull("must block AWS metadata IP", r);
	}

	@Test
	public void blocksMulticast() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("224.0.0.1"), 8080, "224.0.0.1", "");
		assertNotNull(r);
	}

	@Test
	public void blocksPortBelow1024() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 22, "8.8.8.8", "");
		assertNotNull("must block privileged port", r);
		assertTrue(r.toLowerCase().contains("port"));
	}

	@Test
	public void blocksPortZero() throws Exception {
		assertNotNull(SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 0, "8.8.8.8", ""));
	}

	@Test
	public void blocksPortOver65535() throws Exception {
		assertNotNull(SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 70000, "8.8.8.8", ""));
	}

	@Test
	public void allowsPublicHostWithEmptyAllowList() throws Exception {
		// 8.8.8.8 is a public IP; without an allow-list configured, allow it
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 8443, "8.8.8.8", "");
		assertNull("public IP must pass when no allow-list set", r);
	}

	@Test
	public void blocksPublicHostWhenAllowListSetAndMismatched() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 8443, "8.8.8.8",
				"peer1.example.com,peer2.example.com");
		assertNotNull("must block when allow-list set and host not present", r);
		assertTrue(r.contains("allow") || r.contains("publishAllowedHosts"));
	}

	@Test
	public void allowsHostMatchingAllowList() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 8443, "peer1.example.com",
				"peer1.example.com,peer2.example.com");
		assertNull("must allow when host token matches allow-list entry", r);
	}

	@Test
	public void allowListMatchIsCaseInsensitive() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 8443, "Peer1.Example.COM",
				"peer1.example.com");
		assertNull(r);
	}

	@Test
	public void allowListEntriesAreTrimmed() throws Exception {
		String r = SubmissionService.isPublishTargetBlocked(addr("8.8.8.8"), 8443, "peer1.example.com",
				"  peer1.example.com  ,  peer2.example.com  ");
		assertNull(r);
	}
}
