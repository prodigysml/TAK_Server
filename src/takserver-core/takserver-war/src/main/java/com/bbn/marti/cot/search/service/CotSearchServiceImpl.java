

package com.bbn.marti.cot.search.service;

import java.util.AbstractMap.SimpleEntry;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.bbn.marti.cot.search.CotSearchQueryMap;
import com.bbn.marti.cot.search.model.CotSearch;
import com.bbn.marti.cot.search.model.CotSearchStatus;
import com.bbn.marti.cot.search.model.query.DeliveryProtocol;
import com.bbn.marti.cot.search.model.query.ImageOption;

/*
 * 
 */
public class CotSearchServiceImpl implements CotSearchService {

    // Each query loads its results into memory and holds a DB connection, so only a few
    // run at once and a few more may wait; the rest are refused (the servlet answers 503).
    private static final int QUERY_THREADS = Integer.getInteger("tak.cotquery.threads", 4);
    private static final int QUERY_QUEUE = Integer.getInteger("tak.cotquery.queue", 16);

    // Finished queries stay visible to the status page until this many are tracked;
    // then the oldest finished ones are dropped.
    static final int MAX_TRACKED_QUERIES = Integer.getInteger("tak.cotquery.maxTracked", 1000);

    private static final ExecutorService executor = new ThreadPoolExecutor(QUERY_THREADS, QUERY_THREADS,
            60L, TimeUnit.SECONDS, new ArrayBlockingQueue<>(QUERY_QUEUE), new ThreadPoolExecutor.AbortPolicy());
    
    private static final Logger logger = LoggerFactory.getLogger(CotSearchServiceImpl.class);
    
    @Autowired
    private CotSearchQueryMap cotSearchQueryMap;

    @Override
    public String executeCotQueryAsync(String destination, int port, DeliveryProtocol protocol, String sqlPredicate, List<Object> sqlParameters, Integer resultLimit, Boolean latestOnly, ImageOption images, boolean replayMode, Double replaySpeed) {
    	
    	if (logger.isDebugEnabled()) {
    		logger.debug("executeCotQueryAsync destination: " + destination + " port: " + port + " protocol: " + protocol + " sqlPredicate: " + sqlPredicate + " sqlParameters: " + sqlParameters);
    	}
        
        // generate a unique identifier for this CoT query, which will be used to track the progress of the query and result transmission.
        String queryId = UUID.randomUUID().toString(); 
        
        CotSearch cotSearch = new CotSearch(queryId, "New query " + queryId);
        
        evictFinishedQueries();
        cotSearchQueryMap.put(queryId, cotSearch);
        
        // start CoT query execution in a worker thread from the bounded pool.
        try {
            executor.execute(new CotQueryWorker(destination, port, protocol, sqlPredicate, sqlParameters,
                    CotQueryLimits.clampMaximumResults(resultLimit), latestOnly, images, replayMode, replaySpeed, cotSearch));
        } catch (RejectedExecutionException e) {
            cotSearchQueryMap.remove(queryId);
            throw e;
        }
        
        logger.debug("queryId: " + queryId + " cotSearch: " + cotSearch);
        
        return queryId;
    }

    /** Keeps the status map bounded by dropping the oldest finished queries. */
    private void evictFinishedQueries() {
        int excess = cotSearchQueryMap.size() - MAX_TRACKED_QUERIES + 1;
        if (excess <= 0) {
            return;
        }
        // sort on a snapshot of the timestamps: they keep changing while workers run
        cotSearchQueryMap.values().stream()
                .filter(s -> s.getStatus() == CotSearchStatus.DONE || s.getStatus() == CotSearchStatus.ERROR)
                .map(s -> new SimpleEntry<String, Long>(s.getId(), s.getTimestamp() == null ? 0L : s.getTimestamp().getTime()))
                .sorted(Comparator.comparingLong(SimpleEntry::getValue))
                .limit(excess)
                .forEach(e -> cotSearchQueryMap.remove(e.getKey()));
    }
}
