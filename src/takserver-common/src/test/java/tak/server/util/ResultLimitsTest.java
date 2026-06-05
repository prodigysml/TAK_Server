package tak.server.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public class ResultLimitsTest {

	@Test
	public void exceedsCap_boundary() {
		assertFalse(ResultLimits.exceedsCap(0, 100));
		assertFalse(ResultLimits.exceedsCap(100, 100));
		assertTrue(ResultLimits.exceedsCap(101, 100));
	}

	@Test
	public void exceedsCap_nonPositiveCapMeansNoCap() {
		assertFalse(ResultLimits.exceedsCap(1_000_000, 0));
		assertFalse(ResultLimits.exceedsCap(1_000_000, -1));
	}

	@Test
	public void bounded_withinCap_returnsAllElements() {
		List<Integer> src = Arrays.asList(1, 2, 3);
		assertEquals(src, ResultLimits.bounded(src, 10));
		assertEquals(src, ResultLimits.bounded(src, 3));
	}

	@Test
	public void bounded_overCap_truncatesInOrder() {
		List<Integer> src = Arrays.asList(1, 2, 3, 4, 5);
		assertEquals(Arrays.asList(1, 2, 3), ResultLimits.bounded(src, 3));
	}

	@Test
	public void bounded_nonPositiveCap_returnsAll() {
		List<Integer> src = Arrays.asList(1, 2, 3);
		assertEquals(src, ResultLimits.bounded(src, 0));
		assertEquals(src, ResultLimits.bounded(src, -5));
	}

	@Test
	public void bounded_nullInput_returnsEmpty() {
		assertTrue(ResultLimits.bounded(null, 10).isEmpty());
	}
}
