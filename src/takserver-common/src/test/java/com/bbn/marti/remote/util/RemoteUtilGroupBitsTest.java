package com.bbn.marti.remote.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import com.bbn.marti.remote.groups.Direction;
import com.bbn.marti.remote.groups.Group;

/**
 * Group bit positions that don't fit the vector are skipped instead of throwing
 * on the message path: an out-of-range bitpos used to be logged and then written
 * anyway (ArrayIndexOutOfBoundsException), and a vector shorter than a group's
 * bitpos threw StringIndexOutOfBoundsException.
 */
public class RemoteUtilGroupBitsTest {

	private final RemoteUtil util = new RemoteUtil();

	private static Group group(String name, int bitpos) {
		Group g = new Group(name, Direction.IN);
		g.setBitpos(bitpos);
		return g;
	}

	@Test
	public void outOfRangeBitposIsSkipped() {
		boolean[] bits = util.getBitVectorForGroups(Set.of(group("ok", 3), group("big", RemoteUtil.GROUPS_BIT_VECTOR_LEN),
				group("negative", -1)), Direction.IN.getValue());

		assertTrue(bits[3]);
		int set = 0;
		for (boolean b : bits) {
			if (b) {
				set++;
			}
		}
		assertEquals(1, set);
	}

	@Test
	public void groupPastAShortVectorIsNotAMember() {
		// "0101" reversed: bitpos 0 and 2 set
		Group in = group("in", 2);
		Group past = group("past", 10);
		Set<Group> found = util.getGroupsForBitVectorString("0101", List.of(in, past, group("out", 1)));

		assertTrue(found.contains(in));
		assertFalse(found.contains(past));
		assertEquals(1, found.size());
	}
}
