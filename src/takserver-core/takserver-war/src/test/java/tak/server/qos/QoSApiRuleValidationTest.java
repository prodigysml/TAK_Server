package tak.server.qos;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import com.bbn.marti.config.RateLimitRule;

public class QoSApiRuleValidationTest {

	private static RateLimitRule rule(Integer threshold, Integer rate) {
		RateLimitRule r = new RateLimitRule();
		r.setClientThresholdCount(threshold);
		r.setReportingRateLimitSeconds(rate);
		return r;
	}

	@Test
	public void acceptsNormalRules() {
		QoSApi.validateRateLimitRules(Arrays.asList(rule(0, 0), rule(100, 5), rule(500, 30)));
	}

	@Test
	public void acceptsMaxRules() {
		List<RateLimitRule> rules = new ArrayList<>();
		for (int i = 0; i < QoSApi.MAX_RATE_LIMIT_RULES; i++) {
			rules.add(rule(i, 1));
		}
		QoSApi.validateRateLimitRules(rules);
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNull() {
		QoSApi.validateRateLimitRules(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsEmpty() {
		QoSApi.validateRateLimitRules(Collections.emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsTooMany() {
		List<RateLimitRule> rules = new ArrayList<>();
		for (int i = 0; i <= QoSApi.MAX_RATE_LIMIT_RULES; i++) {
			rules.add(rule(i, 1));
		}
		QoSApi.validateRateLimitRules(rules);
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNegativeThreshold() {
		QoSApi.validateRateLimitRules(Arrays.asList(rule(-1, 5)));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNegativeRate() {
		QoSApi.validateRateLimitRules(Arrays.asList(rule(10, -5)));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsMissingValues() {
		QoSApi.validateRateLimitRules(Arrays.asList(rule(10, null)));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNullRule() {
		QoSApi.validateRateLimitRules(Arrays.asList(rule(1, 1), null));
	}
}
