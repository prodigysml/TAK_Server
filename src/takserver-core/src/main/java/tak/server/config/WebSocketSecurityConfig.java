package tak.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.messaging.MessageSecurityMetadataSourceRegistry;
import org.springframework.security.config.annotation.web.socket.AbstractSecurityWebSocketMessageBrokerConfigurer;

import tak.server.Constants;

@Configuration
@Profile({Constants.API_PROFILE_NAME, Constants.MONOLITH_PROFILE_NAME})
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

	protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {

	    // require the listed roles for access
	    messages.simpDestMatchers("/cop/*").hasAnyRole("ANONYMOUS", "WEBCOP", "ADMIN");
	}
	
	// disable CSRF token requirement
	// Cross-site use of the session is still refused: /Marti/api/cop is registered
	// with no allowed origins (WebSocketConfiguration.registerStompEndpoints), so
	// Spring's origin check at the handshake (WebSocket and SockJS) accepts only
	// same-origin pages. Don't add allowed origins there without turning this back on.
	// http://docs.spring.io/spring-security/site/docs/current/reference/html/websocket.html#websocket-sameorigin
	// Turn this back on when we've put it in the STOMP headers:
	// http://docs.spring.io/spring-security/site/docs/current/reference/html/websocket.html#websocket-sameorigin-csrf
	@Override
    protected boolean sameOriginDisabled() {
        return true;
    }
}
