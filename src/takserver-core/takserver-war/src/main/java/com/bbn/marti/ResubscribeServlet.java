

package com.bbn.marti;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;

import com.bbn.security.web.MartiValidator;
import com.bbn.security.web.MartiValidatorConstants;

public class ResubscribeServlet extends EsapiServlet {
	private static final long serialVersionUID = 8695971270050381226L;

	// Cap parameters processed per request to bound DB-connection fan-out
	// (CWE-400). Each id opens a fresh JDBC connection in removeSubscription;
	// without a cap a single POST with thousands of parameters can exhaust
	// the connection pool and DoS the servlet.
	static final int MAX_RESUBSCRIBE_PARAMS = Integer.getInteger(
			"tak.resubscribe.maxParams", 256);

	/**
	 * Returns true if the parameter count must be rejected up-front. Extracted
	 * for unit testing.
	 */
	static boolean shouldRejectParamCount(int paramCount, int cap) {
		return paramCount > cap;
	}

	@Autowired
	private JDBCQueryAuditLogHelper wrap;

	@Autowired
	private DataSource ds;

	public ResubscribeServlet() {
		super();
	}

	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, 
				"GET is not supported by ResubscribeServlet");
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		Map<String, String[]> params = new HashMap<String, String[]>(
				request.getParameterMap());
		String context = "ResubscribeServlet";

		initAuditLog(request);

		if (shouldRejectParamCount(params.size(), MAX_RESUBSCRIBE_PARAMS)) {
			log.warning("ResubscribeServlet rejecting request with "
					+ params.size() + " parameters (cap "
					+ MAX_RESUBSCRIBE_PARAMS + ")");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"too many parameters");
			return;
		}

		int processed = 0;
		for (String id : params.keySet()) {
			if (processed++ >= MAX_RESUBSCRIBE_PARAMS) {
				break;
			}
			removeSubscription(id);
		}

		// re-direct back to SubMgr
		String referer = request.getHeader("referer");

		try {
			referer = validator.getValidInput(context, referer, "URL", MartiValidatorConstants.LONG_STRING_CHARS, false);
		} catch (ValidationException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"Bad value for parameter \"referer\":" + e.getMessage());
			return;
		} catch (IntrusionException e) {
			log.severe("Intrusion attempt detected" + e.getMessage());
			response.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"Bad value for parameter \"referer\":" + e.getMessage());
			return;
		}

		response.sendRedirect(referer);
	}

	private void removeSubscription(String id) {
		try (Connection connection = ds.getConnection(); PreparedStatement sqlQuery = wrap
					.prepareStatement("DELETE FROM subscriptions WHERE id=?", connection)) {
			int idInt = Integer.parseInt(id);
			if (idInt < 0) {
				throw new IllegalArgumentException(
						"Subscription ID cannot be negative");
			}
			sqlQuery.setInt(1, idInt);
			wrap.doUpdate(sqlQuery);
		} catch (Exception e) {
			// not sure where this output goes
			// but we're just doing best effort here...
			e.printStackTrace();
		}
	}

	@Override
	protected void initalizeEsapiServlet() {
		this.log = Logger.getLogger(ResubscribeServlet.class.getCanonicalName());		
	}
}
