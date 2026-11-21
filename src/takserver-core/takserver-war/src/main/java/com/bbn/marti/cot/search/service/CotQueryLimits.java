package com.bbn.marti.cot.search.service;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Limits on CoT search queries: how many rows one query may load, and where the
 * server may send the results.
 */
public final class CotQueryLimits {

    /** Used when the caller gives no maximumResults; override with -Dtak.cotquery.defaultMaxResults. */
    static final int DEFAULT_MAX_RESULTS = Integer.getInteger("tak.cotquery.defaultMaxResults", 10_000);

    /** Hard ceiling on maximumResults; override with -Dtak.cotquery.maxResults. */
    static final int MAX_RESULTS = Integer.getInteger("tak.cotquery.maxResults", 100_000);

    static final int MIN_DELIVERY_PORT = 1024;
    static final int MAX_DELIVERY_PORT = 65535;

    private CotQueryLimits() {
    }

    /**
     * Results are loaded into memory before sending, so every query gets a LIMIT:
     * the default when none was asked for, and never more than the ceiling.
     */
    public static int clampMaximumResults(Integer requested) {
        if (requested == null || requested < 1) {
            return Math.min(DEFAULT_MAX_RESULTS, MAX_RESULTS);
        }
        return Math.min(requested, MAX_RESULTS);
    }

    /**
     * Checks where query results would be sent. The server only connects back to the
     * client that asked: {@code hostName} must resolve to {@code remoteAddr}, which must
     * be a routable unicast address, and the port must be unprivileged.
     *
     * @return the address to deliver to, as an IP literal, so delivery does not depend
     *         on a second DNS lookup
     * @throws IllegalArgumentException with a short reason if the target is not allowed
     */
    public static String validateDeliveryTarget(String hostName, int port, String remoteAddr) {
        if (port < MIN_DELIVERY_PORT || port > MAX_DELIVERY_PORT) {
            throw new IllegalArgumentException("port must be between " + MIN_DELIVERY_PORT + " and " + MAX_DELIVERY_PORT);
        }
        if (hostName == null || hostName.isEmpty() || remoteAddr == null || remoteAddr.isEmpty()) {
            throw new IllegalArgumentException("hostName must be the requesting client's address");
        }

        InetAddress client;
        InetAddress[] resolved;
        try {
            client = InetAddress.getByName(remoteAddr);
            resolved = InetAddress.getAllByName(hostName);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("hostName does not resolve");
        }

        if (client.isLoopbackAddress() || client.isLinkLocalAddress() || client.isAnyLocalAddress()
                || client.isMulticastAddress()) {
            throw new IllegalArgumentException("results cannot be delivered to a local or multicast address");
        }

        for (InetAddress candidate : resolved) {
            if (candidate.equals(client)) {
                return client.getHostAddress();
            }
        }
        throw new IllegalArgumentException("hostName must be the requesting client's address");
    }
}
