package com.bbn.marti.network;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.config.AuthType;
import com.bbn.marti.config.Input;

/**
 * Validates that POST /inputs rejects oversized JSON list and string
 * fields before they reach downstream regex / Ignite broadcast paths
 * (CWE-400). An admin session — compromised or otherwise — must not be
 * able to push the server into unbounded validation work by sending an
 * Input definition with a giant filtergroup list, huge iface, or huge
 * multicast group.
 */
public class SubmissionApiInputValidationTest {

	private SubmissionApi api;

	private Input newValidInput() {
		Input i = new Input();
		i.setName("valid_name");
		i.setProtocol("tcp");
		i.setPort(8089);
		i.setAuth(AuthType.ANONYMOUS);
		return i;
	}

	@Before
	public void setUp() {
		api = new SubmissionApi();
	}

	@Test
	public void acceptsValidBaseInput() {
		List<String> errors = api.getValidationErrors(newValidInput());
		assertTrue("expected no errors but got " + errors, errors.isEmpty());
	}

	@Test
	public void rejectsFiltergroupListAboveCap() {
		Input i = newValidInput();
		List<String> fg = i.getFiltergroup();
		for (int n = 0; n < SubmissionApi.MAX_FILTERGROUP_ENTRIES + 1; n++) {
			fg.add("g" + n);
		}
		List<String> errors = api.getValidationErrors(i);
		assertTrue("must reject oversized filtergroup list",
				errors.stream().anyMatch(s -> s.contains("Too many filtergroup")));
	}

	@Test
	public void acceptsFiltergroupListAtCap() {
		Input i = newValidInput();
		List<String> fg = i.getFiltergroup();
		for (int n = 0; n < SubmissionApi.MAX_FILTERGROUP_ENTRIES; n++) {
			fg.add("g" + n);
		}
		List<String> errors = api.getValidationErrors(i);
		assertFalse("at-cap filtergroup must be accepted",
				errors.stream().anyMatch(s -> s.contains("filtergroup")));
	}

	@Test
	public void rejectsFiltergroupEntryTooLong() {
		Input i = newValidInput();
		StringBuilder big = new StringBuilder();
		for (int n = 0; n < SubmissionApi.MAX_FILTERGROUP_ENTRY_LEN + 1; n++) big.append('x');
		i.getFiltergroup().add(big.toString());
		List<String> errors = api.getValidationErrors(i);
		assertTrue("must reject oversized filtergroup entry",
				errors.stream().anyMatch(s -> s.contains("Filtergroup entry too long")));
	}

	@Test
	public void rejectsIfaceAboveCap() {
		Input i = newValidInput();
		StringBuilder big = new StringBuilder();
		for (int n = 0; n < SubmissionApi.MAX_IFACE_LEN + 1; n++) big.append('a');
		i.setIface(big.toString());
		List<String> errors = api.getValidationErrors(i);
		assertTrue("must reject oversized iface",
				errors.stream().anyMatch(s -> s.contains("Interface value too long")));
	}

	@Test
	public void rejectsGroupAboveCap() {
		Input i = newValidInput();
		i.setProtocol("mcast");
		StringBuilder big = new StringBuilder();
		for (int n = 0; n < SubmissionApi.MAX_GROUP_LEN + 1; n++) big.append('1');
		i.setGroup(big.toString());
		List<String> errors = api.getValidationErrors(i);
		assertTrue("must reject oversized multicast group",
				errors.stream().anyMatch(s -> s.contains("Multicast group value too long")));
	}

	@Test
	public void emptyFiltergroupIsValid() {
		List<String> errors = api.getValidationErrors(newValidInput());
		assertFalse(errors.stream().anyMatch(s -> s.contains("filtergroup")));
	}

	@Test
	public void nullFiltergroupIsValid() {
		// New ArrayList<>() inside Input.getFiltergroup() means the field is
		// always non-null, but the validator should still tolerate an empty
		// list without flagging any errors.
		Input i = newValidInput();
		List<String> errors = api.getValidationErrors(i);
		assertFalse(errors.stream().anyMatch(s -> s.contains("filtergroup")));
	}
}
