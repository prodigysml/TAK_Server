

package com.bbn.marti;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.dom4j.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.bbn.marti.util.CommonUtil;

/**
 * Servlet implementation class WriteImageServlet
 */
//@WebServlet("/GetCotData")
public class GetCotDataServlet extends EsapiServlet {

    private static final Logger logger = LoggerFactory.getLogger(GetCotDataServlet.class);

	private static final long serialVersionUID = -1643155275297691951L;

	@Autowired
	private JDBCQueryAuditLogHelper queryWrapper;

	@Autowired
	private DataSource ds;

	@Autowired
	private CommonUtil martiUtil;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public GetCotDataServlet() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}
	
	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
	    
	    initAuditLog(request);
	    
		int cotId = -1;
		String cotUid = null;
		boolean isXml = false;
		
		try {
			cotId = Integer.parseInt(request.getParameter("cotId"));
		} catch (Exception e) { }	
			
		try {
			cotUid = request.getParameter("uid");
		} catch (Exception e) { }
		
		try {
			isXml = request.getParameter("xml") != null;
		} catch (Exception e) { }		
		
		if (cotId < 1 && cotUid == null) {
		    
		    String msg = "either uid or cotId must be specified as a request parameter";
		    
		    response.sendError(400, msg);
		    
			logger.warn(msg);

			return;
		}
		
		// get the group vector for the requesting user
		String groupVector = martiUtil.getGroupBitVector(request);
		if (groupVector == null || groupVector.isEmpty()) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "Unable to determine group vector");
			return;
		}

		Document doc = null;

		// query by cot uid
		if (cotUid != null) {
		    // get latest cot event by uid, filtered by group vector
		    String cotQuery = "SELECT id, uid, cot_type, access, qos, opex, start, time, stale, how, point_hae, point_ce, point_le, detail, servertime, caveat, releaseableto, event_pt, ST_AsText(event_pt) FROM cot_router WHERE uid = ? AND ?::bit(32768) & lpad(groups::character varying, 32768, '0')::bit(32768)::bit varying <> 0::bit(32768)::bit varying ORDER BY id DESC LIMIT 1";
		    try {
		    	try (Connection connection = ds.getConnection(); PreparedStatement stmt = queryWrapper.prepareStatement(cotQuery, connection)) {
		    		stmt.setString(1, cotUid);
		    		stmt.setString(2, groupVector);

		    		try (ResultSet results = queryWrapper.doQuery(stmt)) {

		    			if (results.next() == false) {
		    				response.sendError(404);
		    				return;
		    			}
		    			doc = CotImageBean.buildCot(results);
		    		}
		    	}

		    } catch (Exception e) {
		        logger.warn("exception executing CoT query " + e.getMessage(), e);
		    }

		} else if (cotId >= 0) {
		    // query DB for CoT meta-data on cotId, filtered by group vector
		    String cotQuery = "SELECT id, uid, cot_type, access, qos, opex, start, time, stale, how, point_hae, point_ce, point_le, detail, servertime, caveat, releaseableto, event_pt, ST_AsText(event_pt) FROM cot_router WHERE id = ? AND ?::bit(32768) & lpad(groups::character varying, 32768, '0')::bit(32768)::bit varying <> 0::bit(32768)::bit varying";
		    try (Connection connection = ds.getConnection(); PreparedStatement stmt = queryWrapper.prepareStatement(cotQuery, connection)) {
		        stmt.setInt(1, cotId);
		        stmt.setString(2, groupVector);

		        try (ResultSet results = queryWrapper.doQuery(stmt)) {

		        	if (results.next() == false) {
		        		response.sendError(404);
		        		return;
		        	}

		        	doc = CotImageBean.buildCot(results);
		        }

		    } catch (Exception e) {
		        logger.warn("exception executing CoT query " + e.getMessage(), e);
		    }
		}

		// respond with XML
		if (isXml) {
		    response.setContentType("application/xml");
		    response.getWriter().write(doc.asXML());
		    return;
		}

		// respond with JSON
		response.setContentType("application/json");
		response.getWriter().write(buildJson(doc));
	}

	private static String escapeJson(String value) {
		if (value == null) return "";
		return value.replace("\\", "\\\\").replace("\"", "\\\"")
				.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
	}

	private String buildJson(Document doc) {
		String ret = "{ ";
		if (doc.getRootElement().element("detail") != null
				&& doc.getRootElement().element("detail").element("remarks") != null
				&& doc.getRootElement().element("detail").element("remarks")
						.getText() != null) {
			ret += " \"remarks\" : \""
					+ escapeJson(doc.getRootElement().element("detail").element("remarks")
							.getText()) + "\",";
		}
		ret += " \"uid\" : \"" + escapeJson(doc.getRootElement().attributeValue("uid"))
				+ "\",";
		ret += " \"type\" : \"" + escapeJson(doc.getRootElement().attributeValue("type"))
				+ "\",";
		ret += " \"how\" : \"" + escapeJson(doc.getRootElement().attributeValue("how"))
				+ "\",";
		ret += " \"lat\" : \"" + escapeJson(doc.getRootElement().element("point").attributeValue("lat"))
				+ "\",";
		ret += " \"lon\" : \"" + escapeJson(doc.getRootElement().element("point").attributeValue("lon"))
				+ "\",";
		ret += " \"hae\" : \"" + escapeJson(doc.getRootElement().element("point").attributeValue("hae"))
				+ "\",";
		ret += " \"le\" : \"" + escapeJson(doc.getRootElement().element("point").attributeValue("le"))
				+ "\",";
		ret += " \"ce\" : \"" + escapeJson(doc.getRootElement().element("point").attributeValue("ce"))
				+ "\" }";
		return ret;
	}

    @Override
    protected void initalizeEsapiServlet() { }

}
