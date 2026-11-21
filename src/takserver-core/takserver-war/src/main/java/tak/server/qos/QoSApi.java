
package tak.server.qos;

import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bbn.marti.config.Qos;
import com.bbn.marti.config.RateLimitRule;
import com.bbn.marti.cot.search.model.ApiResponse;
import com.bbn.marti.network.BaseRestController;

import tak.server.Constants;
import tak.server.ignite.MessagingIgniteBroker;

@RestController
public class QoSApi extends BaseRestController {
	
		private static final Logger logger = LoggerFactory.getLogger(QoSApi.class);

		// Rules are persisted to CoreConfig, pushed to every node and walked on each
		// client-count change, so keep the list short. Override with -Dtak.qos.maxRules.
		static final int MAX_RATE_LIMIT_RULES = Integer.getInteger("tak.qos.maxRules", 100);

	    @Autowired
	    private QoSManager qosManager; 
	    
	    @RequestMapping(value = "/qos/delivery/enable", method = RequestMethod.PUT)
	    public void enableDelivery(@RequestBody boolean enable) {
	    	 MessagingIgniteBroker.brokerVoidServiceCalls(service -> ((QoSManager) service).setDeliveryLimiterEnabled(enable),
	    			 Constants.DISTRIBUTED_QOS_MANAGER, QoSManager.class);
	    }
	    
	    @RequestMapping(value = "/qos/delivery/set", method = RequestMethod.PUT)
	    public void setDelivery(@RequestBody List<RateLimitRule> rateLimitRule) {
	    	validateRateLimitRules(rateLimitRule);
	    	MessagingIgniteBroker.brokerVoidServiceCalls(service -> ((QoSManager) service).setDeliveryRules(rateLimitRule),
	    			 Constants.DISTRIBUTED_QOS_MANAGER, QoSManager.class);
	    }
	    
	    @RequestMapping(value = "/qos/read/enable", method = RequestMethod.PUT)
	    public void enableRead(@RequestBody boolean enable) {
	    	 MessagingIgniteBroker.brokerVoidServiceCalls(service -> ((QoSManager) service).setReadLimiterEnabled(enable),
	    			 Constants.DISTRIBUTED_QOS_MANAGER, QoSManager.class);
	    }
	    
	    @RequestMapping(value = "/qos/read/set", method = RequestMethod.PUT)
	    public void setRead(@RequestBody List<RateLimitRule> rateLimitRule) {
	    	validateRateLimitRules(rateLimitRule);
	    	MessagingIgniteBroker.brokerVoidServiceCalls(service -> ((QoSManager) service).setReadRules(rateLimitRule),
	    			 Constants.DISTRIBUTED_QOS_MANAGER, QoSManager.class);
	    }
	    
	    /**
	     * Rejects a rule list that would break or bog down the rate limiter: empty (the
	     * delivery strategy refuses to start without rules), too long, or with missing or
	     * negative values. Thrown IllegalArgumentException maps to 400.
	     */
	    static void validateRateLimitRules(List<RateLimitRule> rules) {
	    	if (rules == null || rules.isEmpty()) {
	    		throw reject("at least one rate limit rule is required");
	    	}
	    	if (rules.size() > MAX_RATE_LIMIT_RULES) {
	    		throw reject("too many rate limit rules (max " + MAX_RATE_LIMIT_RULES + ")");
	    	}
	    	for (RateLimitRule rule : rules) {
	    		if (rule == null
	    				|| rule.getClientThresholdCount() == null || rule.getClientThresholdCount() < 0
	    				|| rule.getReportingRateLimitSeconds() == null || rule.getReportingRateLimitSeconds() < 0) {
	    			throw reject("each rule needs a non-negative clientThresholdCount and reportingRateLimitSeconds");
	    		}
	    	}
	    }

	    private static IllegalArgumentException reject(String message) {
	    	logger.warn("rejected QoS rate limit rules: {}", message);
	    	return new IllegalArgumentException(message);
	    }

	    @RequestMapping(value = "/qos/dos/enable", method = RequestMethod.PUT)
	    public void enableDOS(@RequestBody boolean enable) {
	    	 MessagingIgniteBroker.brokerVoidServiceCalls(service -> ((QoSManager) service).setDOSLimiterEnabled(enable),
	    			 Constants.DISTRIBUTED_QOS_MANAGER, QoSManager.class);
	    }
	    
	    @RequestMapping(value = "/qos/conf", method = RequestMethod.GET)
	    public ApiResponse<Qos> getQosConf() {
	    	return new ApiResponse<Qos>(Constants.API_VERSION, RateLimitRule.class.getSimpleName(), qosManager.qosConf());
	    }	
	    
	    @RequestMapping(value = "/qos/ratelimit/delivery/active", method = RequestMethod.GET)
	    public ApiResponse<Entry<Integer, Integer>> getActiveDeliveryRateLimit() {
	    	return new ApiResponse<Entry<Integer, Integer>>(Constants.API_VERSION, "RateLimit", qosManager.getActiveDeliveryRateThresholdAndLimit());
	    }	
	    
	    @RequestMapping(value = "/qos/ratelimit/read/active", method = RequestMethod.GET)
	    public ApiResponse<Entry<Integer, Integer>> getActiveReadRateLimit() {
	    	return new ApiResponse<Entry<Integer, Integer>>(Constants.API_VERSION, "RateLimit", qosManager.getActiveReadRateThresholdAndLimit());
	    }
	    
	    @RequestMapping(value = "/qos/ratelimit/dos/active", method = RequestMethod.GET)
	    public ApiResponse<Entry<Integer, Integer>> getActiveDOSRateLimit() {
	    	return new ApiResponse<Entry<Integer, Integer>>(Constants.API_VERSION, "RateLimit", qosManager.getActiveDOSRateThresholdAndLimit());
	    }
}
