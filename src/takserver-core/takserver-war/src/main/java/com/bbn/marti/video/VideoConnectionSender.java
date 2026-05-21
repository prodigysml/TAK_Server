/*
 * 
 * The VideoConnectionSender class sends Cot Alias events 
 * 
 */
package com.bbn.marti.video;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.bbn.marti.EsapiServlet;
import com.bbn.marti.remote.RemoteSubscription;
import com.bbn.marti.remote.SubmissionInterface;
import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.util.DateUtil;
import com.bbn.marti.util.CommonUtil;
import com.bbn.marti.remote.util.SpringContextBeanForApi;


//@WebServlet("/vcs/*")
public class VideoConnectionSender extends EsapiServlet { 
	
	private static final long serialVersionUID = -2364103405436785318L;

	@Autowired
	private VideoManagerService videoManagerService;

	@Autowired
	private SubmissionInterface submission;

	@Autowired
	private SubscriptionManagerLite subscriptionManager;
	
    protected static final Logger logger = LoggerFactory.getLogger(VideoConnectionManager.class);
	
    // SECURITY: XML-escape attacker-controlled fields concatenated into the
    // CoT envelope so client-supplied feed metadata cannot inject closing
    // tags or new attributes (CWE-91 / CWE-74).
    private static String xmlEscape(String s) {
    	if (s == null) return "";
    	StringBuilder out = new StringBuilder(s.length());
    	for (int i = 0; i < s.length(); i++) {
    		char c = s.charAt(i);
    		switch (c) {
    			case '&':  out.append("&amp;"); break;
    			case '<':  out.append("&lt;"); break;
    			case '>':  out.append("&gt;"); break;
    			case '"':  out.append("&quot;"); break;
    			case '\'': out.append("&apos;"); break;
    			default:
    				if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') {
    					out.append(c);
    				}
    		}
    	}
    	return out.toString();
    }

    private static String getCotMessage(String senderUid, String destUid, String address, String alias,
    		String port, String roverPort, String rtspReliable, String ignoreEmbeddedKLV,
    		String path, String protocol, String networkTimeout, String bufferTime) {

		String time = DateUtil.toCotTime(System.currentTimeMillis()); // now
		String staleTime = DateUtil.toCotTime(System.currentTimeMillis() + 3600000); // 1 hour from now
		String cot = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
			+ "<event version='2.0' uid='"+xmlEscape(senderUid)+"' type='b-i-v' "
			+ "time='"+time+"' start='"+time+"' stale='"+staleTime+"' how='m-g'>"
			+		"<point lat='0.0' lon='0.0' hae='0.0' ce='0.0' le='0.0' />"
			+ 		"<detail>"
			+			"<__video>"
			+ 				"<ConnectionEntry"
			+ 					" address='" + xmlEscape(address) + "'"
			+ 					" alias='" + xmlEscape(alias) + "'"
			+ 					" port='" + xmlEscape(port) + "'"
			+ 					" roverPort='" + xmlEscape(roverPort) + "'"
			+ 					" rtspReliable='" + xmlEscape(rtspReliable) + "'"
			+ 					" ignoreEmbeddedKLV='" + xmlEscape(ignoreEmbeddedKLV) + "'"
			+ 					" path='" + xmlEscape(path) + "'"
			+ 					" protocol='" + xmlEscape(protocol) + "'"
			+ 					" networkTimeout='" + xmlEscape(networkTimeout) + "'"
			+ 					" bufferTime='" + xmlEscape(bufferTime) + "'"
			+ 				"/>"
			+			"</__video>"
			+ 			"<marti><dest uid='" + xmlEscape(destUid) + "'/></marti>"
			+ 		"</detail>"
			+ "</event>";

		return cot;
    }
    
    private static String[] getContacts(HttpServletRequest request) throws IOException, ServletException {
	    // Get the list of people to send an advertisement to (OPTIONAL)
    	String[] contacts = request.getParameterValues("contacts");
    	if (contacts == null || contacts.length == 0) {
    		List<String> contactList = new LinkedList<String>();
    			for(Part part : request.getParts()) {
    				if (part.getName().equalsIgnoreCase("contacts")) {
    					try(InputStream in = part.getInputStream()) {
							StringWriter writer = new StringWriter();
							IOUtils.copy(in, writer);
							contactList.add(writer.toString());
						}
    				}
    			}
    			contacts = contactList.toArray(new String[contactList.size()]);
	    	}
    	return contacts;
	 }    
    
    @Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) 
			throws ServletException, IOException {
    	
    	try {
        	initAuditLog(request);

			CommonUtil martiUtil = SpringContextBeanForApi.getSpringContext().getBean(CommonUtil.class);

			Objects.requireNonNull(martiUtil, "marti util bean");

			String groupVector = null;

			try {
				// Get group vector for the user associated with this session
				groupVector = martiUtil.getGroupBitVector(request);
				log.finer("groups bit vector: " + groupVector);
			} catch (Exception e) {
				log.fine("exception getting group membership for current web user " + e.getMessage());
			}

    	    String[] contacts = getContacts(request);

    	    // SECURITY: filter contacts to UIDs visible to the caller's groups.
    	    // Without this an authenticated user could send video-feed CoT to any UID.
    	    Set<String> allowedUids = new HashSet<>();
    	    if (groupVector != null && !groupVector.isEmpty()) {
    	        List<RemoteSubscription> visibleSubs = subscriptionManager.getSubscriptionsWithGroupAccess(groupVector, false);
    	        if (visibleSubs != null) {
    	            for (RemoteSubscription sub : visibleSubs) {
    	                if (sub != null && sub.clientUid != null) {
    	                    allowedUids.add(sub.clientUid);
    	                }
    	            }
    	        }
    	    }

           	String[] feedIds = request.getParameter("feedId").split("\\|");
        	for (String feedId : feedIds) {
        		Feed feed = videoManagerService.getFeed(Integer.parseInt(feedId), groupVector);
        		String senderUid = UUID.randomUUID().toString();

	           	for (String contact : contacts) {
	           		if (contact == null || !allowedUids.contains(contact)) {
	           			logger.warn("Dropping video-feed CoT for contact UID '{}' not visible to caller's groups", contact);
	           			continue;
	           		}
	               	String cotMessage = getCotMessage(senderUid, contact, feed.getAddress(), feed.getAlias(),
	               		feed.getPort(), feed.getRoverPort(), feed.getRtspReliable(), feed.getIgnoreEmbeddedKLV(),
	               		feed.getPath(), feed.getProtocol(), feed.getNetworkTimeout(), feed.getBufferTime());

	                submission.submitCot(cotMessage, martiUtil.getGroupsFromRequest(request));
	           	}
        	}
           	
	    } catch (Exception e) {
	        e.printStackTrace();
	        logger.error("Exception!", e);
	        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
 	    }
    }        
    		    
	@Override
	protected void initalizeEsapiServlet() {
		
	}
}
