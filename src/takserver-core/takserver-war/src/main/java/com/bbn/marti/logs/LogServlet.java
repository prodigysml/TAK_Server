package com.bbn.marti.logs;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.bbn.marti.email.EmailClient;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.codec.Base64;

import com.bbn.marti.EsapiServlet;
import com.bbn.marti.HttpParameterConstraints;
import com.bbn.security.web.MartiValidatorConstants;


public class LogServlet extends EsapiServlet {
	
	@Autowired
	private PersistenceStore persistenceStore;

	public enum QueryParameter {
		id,
		uid,
		callsign,
		platform,
		majorVersion,
		minorVersion
	}	
	
	protected Map<String, HttpParameterConstraints> requiredPostParameters;
	protected Map<String, HttpParameterConstraints> optionalPostParameters;
	protected Map<String, HttpParameterConstraints> requiredGetParameters;
	protected Map<String, HttpParameterConstraints> optionalGetParameters;
	private static final long serialVersionUID = 3520164783651907004L;
	private static final org.slf4j.Logger logger = LoggerFactory.getLogger(LogServlet.class);
		
	@Override
	protected void initalizeEsapiServlet()
	{
		logger.debug("initializeEsapiServlet");
		
		requiredPostParameters = new HashMap<String, HttpParameterConstraints>();
		optionalPostParameters = new HashMap<String, HttpParameterConstraints>();		
		requiredPostParameters.put(QueryParameter.uid.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.LONG_STRING_CHARS));
		requiredPostParameters.put(QueryParameter.callsign.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.DEFAULT_STRING_CHARS));
		requiredPostParameters.put(QueryParameter.platform.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.DEFAULT_STRING_CHARS));
		requiredPostParameters.put(QueryParameter.majorVersion.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.DEFAULT_STRING_CHARS));
		requiredPostParameters.put(QueryParameter.minorVersion.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.DEFAULT_STRING_CHARS));

		requiredGetParameters = new HashMap<String, HttpParameterConstraints>();
		optionalGetParameters = new HashMap<String, HttpParameterConstraints>();		
		requiredGetParameters.put(QueryParameter.id.name(), new HttpParameterConstraints(
				MartiValidatorConstants.Regex.MartiSafeString, MartiValidatorConstants.LONG_STRING_CHARS));
	}

	private static final long MAX_UNCOMPRESSED_ENTRY_SIZE = 50 * 1024 * 1024;
	private static final long MAX_UNCOMPRESSED_TOTAL_SIZE = 200 * 1024 * 1024;
	private static final int MAX_ZIP_ENTRIES = 1024;
	private static final long MAX_COMPRESSION_RATIO = 100;

	private HashMap<String, byte[]> extractMissionPackage(byte[] missionPackage) throws IOException {
		HashMap<String, byte[]> files = new HashMap<>();

		ZipEntry entry;
		final int BUFFER = 2048;
		long totalBytes = 0;
		int entryCount = 0;

		ByteArrayInputStream bis = new ByteArrayInputStream(missionPackage);
		ZipInputStream zis = new ZipInputStream(new BufferedInputStream(bis));
		while ((entry = zis.getNextEntry()) != null) {

			if (++entryCount > MAX_ZIP_ENTRIES) {
				throw new IOException("ZIP archive exceeds maximum entry count of " + MAX_ZIP_ENTRIES);
			}
			String entryName = entry.getName();
			if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
				throw new IOException("ZIP entry has illegal path: " + entryName);
			}

			// skip directories
			if (entry.isDirectory()) {
				continue;
			}

			// load in the file
			int count;
			long entryBytes = 0;
			long compressedSize = entry.getCompressedSize();
			byte data[] = new byte[BUFFER];
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			while ((count = zis.read(data, 0, BUFFER)) != -1) {
				entryBytes += count;
				totalBytes += count;
				if (entryBytes > MAX_UNCOMPRESSED_ENTRY_SIZE) {
					throw new IOException("ZIP entry exceeds maximum uncompressed size");
				}
				if (totalBytes > MAX_UNCOMPRESSED_TOTAL_SIZE) {
					throw new IOException("ZIP archive exceeds maximum total uncompressed size");
				}
				if (compressedSize > 0 && entryBytes / compressedSize > MAX_COMPRESSION_RATIO) {
					throw new IOException("ZIP entry compression ratio exceeds maximum, possible zip bomb");
				}
				bos.write(data, 0, count);
			}
			bos.flush();
			bos.close();

			files.put(new File(entry.getName()).getName(), bos.toByteArray());
		}
		zis.close();

		return files;
	}
		
    @Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) 
			throws ServletException, IOException {
    	
    	try {
        	initAuditLog(request);
    		
            Map<String, String[]> httpParameters = validateParams("Log", request, response,
            		requiredPostParameters, optionalPostParameters);

            if (httpParameters == null)
                return;
    		
	      	String uid = getParameterValue(httpParameters, QueryParameter.uid.name());
	      	String callsign = getParameterValue(httpParameters, QueryParameter.callsign.name());
	      	String platform = getParameterValue(httpParameters, QueryParameter.platform.name());
	      	String majorVersion = getParameterValue(httpParameters, QueryParameter.majorVersion.name());
	      	String minorVersion = getParameterValue(httpParameters, QueryParameter.minorVersion.name());
	      	// limit upload size to 50 MB to prevent memory exhaustion
	      	final int MAX_LOG_UPLOAD_SIZE = 50 * 1024 * 1024;
	      	if (request.getContentLength() > MAX_LOG_UPLOAD_SIZE) {
	      		response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, "Payload too large");
	      		return;
	      	}
	      	String encodedString = IOUtils.toString(request.getInputStream());
	    	      		      	
	      	final int BUFFER = 2048;
	      	byte[] zip = Base64.decode(encodedString.getBytes());

			HashMap<String, byte[]> missionPackage = extractMissionPackage(zip);
			Iterator it = missionPackage.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, byte[]> missionPackageEntry = (Map.Entry<String, byte[]>) it.next();

				// create a Log object and store in the db
				Log log = new Log();
				log.setUid(uid);
				log.setCallsign(callsign);
				log.setPlatform(platform);
				log.setMajorVersion(majorVersion);
				log.setMinorVersion(minorVersion);
				log.setContents(missionPackageEntry.getValue());
				log.setFilename(missionPackageEntry.getKey());
				persistenceStore.addLog(log);

				if (CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail() != null &&
						CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail().isLogAlertsEnabled()) {

					for (String extension : CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail().getLogAlertsExtension()) {
						if (log.getFilename().endsWith(extension)) {
							sendLogAlert(log.getContents());
							break;
						}
					}
				}
			}

    	}
    	catch (Exception e) {
    		logger.error("exception in doPost", e);
        	response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    	}
	    	
      	return;
    }

    private void sendLogAlert(byte[] feedback) {
		if (CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail() == null) {
			logger.error("missing email configuration in sendLogAlert");
			return;
		}

		//
		// inspect the log content as a zip file and look for any json content to include
		// summary information in the alert email body
		//
		String body = "";
		try {
			HashMap<String, byte[]> logAsZip = extractMissionPackage(feedback);
			Iterator it = logAsZip.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, byte[]> feedbackFile = (Map.Entry<String, byte[]>) it.next();
				if (feedbackFile.getKey().toLowerCase().contains(".json")) {
					final Map<String, Object> jsonMap =
							new ObjectMapper().readValue(feedbackFile.getValue(), Map.class);
					for (Map.Entry<String, Object> jsonEntry : jsonMap.entrySet()) {
						// Do not include user-supplied email addresses - prevents mail relay abuse
						if (!"Email".equals(jsonEntry.getKey())) {
							body += jsonEntry.getKey() + " : " + jsonEntry.getValue() + "\n";
						}
					}
				}
			}
		} catch (Exception e) {
			if (logger.isDebugEnabled()) {
				logger.debug("exception extracting log as zip");
			}
		}

		if (body != null && !body.isEmpty()) {
			// Only send to the server-configured recipient, no CC, no user-supplied attachments
			EmailClient.sendEmail(
					CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail(),
					CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail().getLogAlertsSubject(),
					body,
					CoreConfigFacade.getInstance().getRemoteConfiguration().getEmail().getLogAlertsTo(),
					null, null);
		}
	}

    @Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) 
			throws ServletException, IOException {
    	
        try {
        	initAuditLog(request);
        	
            Map<String, String[]> httpParameters = validateParams("Log", request, response,
            		requiredGetParameters, optionalGetParameters);

            if (httpParameters == null)
                return;
    		
	      	String id = getParameterValue(httpParameters, QueryParameter.id.name());
	      	String[] ids = id.split(",");

	      	if (ids.length == 1) {
				if (ids[0].equals("ALL")) {
					//
					// collect up all log ids to return in a single zip
					//
					List<String> idList = new LinkedList<>();
					for (Log log : persistenceStore.getLogs(
							null, null, false, false)) {
						idList.add(Integer.toString(log.getId()));
					}
					ids = idList.toArray(new String[0]);
				} else {
					//
					// return the single file in it's original form
					//
					int logId = Integer.parseInt(ids[0]);
					Log log = persistenceStore.getLog(logId);

					response.setContentType("text/plain");
					int contentLength = log.getContents().length;
					response.setContentLength(contentLength);
					String contentDisposition = "attachment; filename=" + ids[0] + "_" + log.getFilename();
					contentDisposition = validator.getValidInput("Content Disposition", contentDisposition, "Filename", MartiValidatorConstants.DEFAULT_STRING_CHARS, false);
					response.addHeader("Content-Disposition", contentDisposition);
					response.getOutputStream().write(log.getContents());
					return;
				}
			}
	      	
	      	//
	      	// return the selected files as a zip
	      	//
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			BufferedOutputStream bos = new BufferedOutputStream(baos);
			ZipOutputStream zos = new ZipOutputStream(bos);

			for (String nextId : ids)
			{
				int logId = Integer.parseInt(nextId);
				Log log = persistenceStore.getLog(logId);
				if (log == null) {
					logger.error("Unable to find logId : " + logId);
					continue;
				}

				String safeFilename = new java.io.File(log.getFilename()).getName().replace("..", "_");
				zos.putNextEntry(new ZipEntry(nextId + "_" + safeFilename));
				zos.write(log.getContents());
				zos.closeEntry();
			}
			zos.close();

			response.setContentType("application/zip");
			int contentLength = baos.size();
			response.setContentLength(contentLength);

			String date = new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss").format(new Date());
			String filename = "LogExport" + date + ".zip";
			response.addHeader(
					"Content-Disposition",
					"attachment; filename=" + filename);

		   response.getOutputStream().write(baos.toByteArray());

	    } catch (Exception e) {
	        logger.error("Exception!", e);
	        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	    }        
    }
    
    @Override
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) 
			throws ServletException, IOException {
        try {
        	initAuditLog(request);
        	
        	String id = request.getParameter("id");
        	persistenceStore.deleteLog(id);
        	
	    } catch (Exception e) {
	        logger.error("Exception!", e);
	        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	    }        
    }    
}
