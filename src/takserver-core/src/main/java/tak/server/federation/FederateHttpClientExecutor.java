package tak.server.federation;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

//import org.apache.http.client.HttpClient;
//import org.apache.http.config.Registry;
//import org.apache.http.config.RegistryBuilder;
//import org.apache.http.conn.socket.ConnectionSocketFactory;
//import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
//import org.apache.http.conn.socket.PlainConnectionSocketFactory;
//import org.apache.http.conn.ssl.NoopHostnameVerifier;
//import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
//import org.apache.http.impl.client.HttpClientBuilder;
//import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
//import org.apache.http.ssl.SSLInitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.remote.exception.TakException;
import com.bbn.marti.service.SSLConfig;

import com.bbn.marti.remote.config.CoreConfigFacade;
import org.apache.hc.client5.http.fluent.Executor;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLInitializationException;
import org.apache.hc.core5.util.TimeValue;

/*
 * 
 * Extend the fluent-hc Executor class so that we can control the http connection pool and SSL/TLS configuration, getting it in the same way as the federate ssl context.
 * This class can no longer extends Executor as Executor has no accessible constructor.
 */
public class FederateHttpClientExecutor {

    private static final Logger logger = LoggerFactory.getLogger(FederateHttpClientExecutor.class);
    
    final static PoolingHttpClientConnectionManager connectionManager;
    //final static HttpClient federateHttpClient;
    final static CloseableHttpClient federateHttpClient;
    
    static SSLContext sslContext = null;
    
    static LayeredConnectionSocketFactory sslSocketFactory = null;

    static {
        
        try {
            sslSocketFactory = SSLConnectionSocketFactory.getSystemSocketFactory();
            
            try {

                Configuration config = CoreConfigFacade.getInstance().getInstance().getRemoteConfiguration();
                
                if (logger.isTraceEnabled()) {
                	logger.trace("federation: " + config.getFederation());
                }

                if (config.getFederation() == null || config.getFederation().getFederationServer() == null || config.getFederation().getFederationServer().getTls() == null) {
                    throw new TakException("Federation TLS configuration not found - unable to initialize federate TLS HTTP client");
                }

                sslContext = SSLConfig.getInstance(CoreConfigFacade.getInstance().getRemoteConfiguration().getFederation().getFederationServer().getTls()).getSSLContext();
                
                if (logger.isTraceEnabled()) {
                	logger.trace("sslContext: " + sslContext);
                }

                // The URL uses the federate's IP address, which its certificate rarely
                // names, so plain hostname verification would refuse most federates.
                // Accepting any certificate the federation truststore trusts (as this
                // used to) lets any federate's cert impersonate another. See peerVerifier.
                sslSocketFactory = new SSLConnectionSocketFactory(sslContext, peerVerifier(new DefaultHostnameVerifier()));
                
            } catch (SecurityException e) {
                throw new TakException("exception initializing federate TLS http executor", e);
            }
        } catch (final SSLInitializationException e) {
            throw new TakException("TLS initialization exeception", e);
        }

        final Registry<ConnectionSocketFactory> sfr = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", sslSocketFactory != null ? sslSocketFactory : SSLConnectionSocketFactory.getSocketFactory())
                .build();

        // Set up http connection pool. TODO: move these settings to federation config
        connectionManager = new PoolingHttpClientConnectionManager(sfr);
        connectionManager.setDefaultMaxPerRoute(100);
        connectionManager.setMaxTotal(200);
        //connectionManager.setValidateAfterInactivity(1000);
        connectionManager.setValidateAfterInactivity(TimeValue.ofMilliseconds(1000));
        //federateHttpClient = HttpClientBuilder.create(). (connectionManager).build();
        federateHttpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    // SHA-256 fingerprints of the certificates each federate address has
    // authenticated with on its federation connection
    private static final Map<String, Set<String>> knownPeers = new ConcurrentHashMap<>();

    /**
     * Records the certificate a federate authenticated with on its federation
     * connection, so an HTTPS call to that address may present the same one.
     */
    public static void expectPeer(String address, X509Certificate cert) {
        String fingerprint = fingerprint(cert);
        if (address != null && fingerprint != null) {
            knownPeers.computeIfAbsent(address, k -> ConcurrentHashMap.newKeySet()).add(fingerprint);
        }
    }

    /**
     * Accepts the HTTPS peer when its certificate names the host (normal hostname
     * verification), or when it is the certificate the federate at that address
     * authenticated with on its federation connection.
     */
    static HostnameVerifier peerVerifier(HostnameVerifier hostnameVerifier) {
        return (host, session) -> {
            if (hostnameVerifier.verify(host, session)) {
                return true;
            }
            String presented = peerFingerprint(session);
            Set<String> expected = knownPeers.get(host);
            if (presented != null && expected != null && expected.contains(presented)) {
                return true;
            }
            logger.error("refusing federate HTTPS peer {}: its certificate neither names the host nor matches the federate's federation connection", host);
            return false;
        };
    }

    private static String peerFingerprint(SSLSession session) {
        try {
            Certificate[] chain = session.getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate ? fingerprint((X509Certificate) chain[0]) : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String fingerprint(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            StringBuilder sb = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static Executor newInstance() {
        logger.trace("getting fluent pooling tls http executor: " + federateHttpClient);

//        return new Executor(federateHttpClient);
        return Executor.newInstance(federateHttpClient);
    }

//    FederateHttpClientExecutor(CloseableHttpClient httpclient) {
//        super(httpclient);
//    }
    
}
