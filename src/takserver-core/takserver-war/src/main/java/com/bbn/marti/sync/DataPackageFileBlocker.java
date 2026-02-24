package com.bbn.marti.sync;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.DocumentSource;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bbn.marti.sync.model.Resource;
import com.bbn.marti.util.missionpackage.MissionPackage;

public class DataPackageFileBlocker {

    private static final Logger logger = LoggerFactory.getLogger(DataPackageFileBlocker.class);

    private static final long MAX_UNCOMPRESSED_ENTRY_SIZE = 50 * 1024 * 1024;  // 50 MB per entry
    private static final long MAX_UNCOMPRESSED_TOTAL_SIZE = 200 * 1024 * 1024; // 200 MB total
    private static final int MAX_ZIP_ENTRIES = 1024;
    private static final long MAX_COMPRESSION_RATIO = 100;

    public static byte[] blockCoT(Metadata metadata, byte[] content, String cotFilter) {
        try {

            if (Arrays.asList(metadata.getKeywords()).contains("missionpackage")) {
                // iterate across the contents of the mission package
                Map<String, byte[]> missionPackage = MissionPackage.extractMissionPackage(content);
                for (Map.Entry<String, byte[]> missionPackageFile : missionPackage.entrySet()) {

                    // inspect .cot files
                    String filename = missionPackageFile.getKey();
                    if (filename.endsWith(".cot")) {

                        // block the data package if a .cot file contains the filter value
                        String cot = new String(missionPackageFile.getValue());
                        if (cot.contains(cotFilter)) {
                            return null;
                        }
                    }
                }
            }

            return content;

        } catch (Exception e) {
            logger.error("exception in blockCoTDetail!", e);
            return null;
        }
    }

    public static byte[] blockResourceContent(Metadata metadata, byte[] content, String fileExt) {

        Resource res = new Resource(metadata);
        Objects.requireNonNull(res, "resource metadata");
        Objects.requireNonNull(content, "resource content bytes");

        String resourceFileName = res.getFilename();
        debugInfo(fileExt, res, resourceFileName);

        final String finalFileExt = "." + fileExt;

        if (res.getKeywords().contains("ARCHIVED_MISSION")) {
            if (logger.isDebugEnabled()) {
                logger.debug(" this request is to archive a mission, we don't need to inspect it");
            }
            return content;
        }
        // handle mission packages and data packages
        if (res.getKeywords().contains("missionpackage")) {
            logger.debug(" mission package");
            if (!containsEntry(zipEntry -> zipEntry.getName().endsWith(finalFileExt), content)) {
                logger.info("blocked files are not contained in the resource: " + finalFileExt);
                return content;
            } else {
                logger.debug(" updating manifest for mission package");
                return updateManifestInMissionPackage(content, finalFileExt);
            }
        }
        // logger.debug(" is there a blocked file in the contents " + containsEntry(zipEntry -> zipEntry.getName().endsWith(finalFileExt), content));

        // adding a file to a mission, check if file is blocked
        if (resourceFileName.endsWith(finalFileExt)) {
            logger.debug(" file is blocked, not submitting to federate rol: " + resourceFileName);
            return null;  // skip this file, single files are not mission packages
        } else {
            logger.debug(" file is not blocked, submitting to federate rol: " + resourceFileName);
            return content; // file is not blocked so submit it
        }
    }

    private static void debugInfo(String fileExt, Resource res, String resourceFileName) {
        if (logger.isTraceEnabled()) {
            logger.trace(" what are the keywords: " + res.getKeywords());
            logger.trace(" what is  the fileExt from the server: " + fileExt);
            logger.trace(" what is the file name: " + resourceFileName);
        }
    }

    private static byte[] updateManifestInMissionPackage(byte[] content, String fileExt) {

        byte[] updatedContent = null;
        try (
                ByteArrayInputStream bis = new ByteArrayInputStream(content);
                ZipInputStream zis = new ZipInputStream(bis);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ZipOutputStream zos = new ZipOutputStream(bos)
        ) {

            String manifestEntryName = null;
            String manifestContent = "";
            int addedEntry = 0;
            byte[] updatedManifest = null;
            long totalBytes = 0;
            int entryCount = 0;
            final int BUFFER = 2048;

            ZipEntry entry;
            // copy the contents and make changes as needed
            while ((entry = zis.getNextEntry()) != null) {
                if (++entryCount > MAX_ZIP_ENTRIES) {
                    throw new IOException("ZIP archive exceeds maximum entry count of " + MAX_ZIP_ENTRIES);
                }

                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    throw new IOException("ZIP entry has illegal path: " + entryName);
                }

                if (logger.isDebugEnabled()) {
                    logger.debug(" get name " + entryName);
                }
                if (entryName.endsWith(fileExt)) {
                    if (logger.isInfoEnabled()) {
                        logger.info("skipping " + entryName);
                    }
                    continue; //skip blocked file
                }
                if (! entryName.contains("manifest.xml")) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(" adding entry " + entryName);
                    }
                    ZipEntry copyEntry = new ZipEntry(entryName);
                    zos.putNextEntry(copyEntry);
                    addedEntry++;
                    // Bounded copy instead of unbounded IOUtils.copy
                    int count;
                    long entryBytes = 0;
                    long compressedSize = entry.getCompressedSize();
                    byte[] buf = new byte[BUFFER];
                    while ((count = zis.read(buf, 0, BUFFER)) != -1) {
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
                        zos.write(buf, 0, count);
                    }
                    zos.closeEntry();
                    continue; // copy in non-manifest file and non-blocked file
                }

                manifestContent = getManifestContent(zis, entry, totalBytes);
                totalBytes += manifestContent.length();
                if (manifestContent.contains(fileExt)) {
                    manifestEntryName = entry.getName();
                }
            }
            // add in the updated manifest
            if (logger.isDebugEnabled()) {
                logger.debug(" the added entries are " + addedEntry);
            }
            if (addedEntry > 0) {
                if (manifestContent.contains(fileExt)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("remove entry in manifest  : " + manifestEntryName);
                    }
                    updatedManifest = removeFileEntry(manifestContent, fileExt);
                }
                if (updatedManifest != null) {
                    // update the archive with the new manifest
                    ZipEntry newEntry = new ZipEntry(manifestEntryName);
                    if (logger.isTraceEnabled()) {
                        logger.trace("adding back in the manifest: " + newEntry.getName() +
                                " the new manifest is : " + new String(updatedManifest));
                    }
                    zos.putNextEntry(newEntry);
                    zos.write(updatedManifest);
                    zos.closeEntry();
                }  else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("manifest missing or is null ");
                    }
                }
                bos.close();
                bis.close();
                zos.close();
                zis.close();
                updatedContent = bos.toByteArray();
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("no entries added ");
                }
            }
            bos.close();
            bis.close();
            zos.close();
            zis.close();
        } catch (IOException e) {
            if (logger.isErrorEnabled()) {
                logger.error(" exception processing mission package files", e);
            }
        }

        return updatedContent;
    }


    private static byte [] removeFileEntry(String manifest, String fileExt) {
        byte[] updatedManifest = null;
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            StreamResult result = new StreamResult(bout);

            SAXReader reader = new SAXReader();

            Document doc = null;

            doc = reader.read(new ByteArrayInputStream(manifest.getBytes()));

            for (Object node : doc.selectNodes("//MissionPackageManifest/Contents/Content/@zipEntry")) {
                String nodeName = ((Attribute) node).getValue();
                if (logger.isTraceEnabled()) {
                    logger.trace("looking at the nodes " + nodeName);
                }
                if (nodeName.endsWith(fileExt)) {
                    ((Attribute) node).getParent().detach();
                    if (logger.isDebugEnabled()) {
                        logger.debug("removed node " + nodeName);
                    }
                }
            }
            List<Node> prunedNodes = doc.selectNodes("//MissionPackageManifest/Contents/Content/@zipEntry");
            if (logger.isTraceEnabled()) {
                logger.trace(" how many nodes are left " + prunedNodes.size());
            }
            if (prunedNodes.size() < 1) {
                return null;
            }
            transformer.transform(new DocumentSource(doc), result);
            updatedManifest = bout.toByteArray();
        } catch (TransformerException | DocumentException e) {
            if (logger.isErrorEnabled())
                logger.error("error updating manifest ", e);
        }
        if (logger.isTraceEnabled()) {
            logger.trace("updated manifest " + new String(updatedManifest));
        }
        return updatedManifest;
    }

    private static boolean containsEntry(Predicate<ZipEntry> filter, byte[] content) {

        try (ByteArrayInputStream bis = new ByteArrayInputStream(content);
             ZipInputStream zis = new ZipInputStream(bis)) {

            ZipEntry entry;
            int entryCount = 0;
            while ((entry = zis.getNextEntry()) != null) {
                if (++entryCount > MAX_ZIP_ENTRIES) {
                    logger.error("ZIP archive exceeds maximum entry count of " + MAX_ZIP_ENTRIES);
                    return false;
                }
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    logger.error("ZIP entry has illegal path: " + entryName);
                    return false;
                }
                if (logger.isTraceEnabled()) {
                    logger.trace(" what is the entry name in contains entry " + entryName);
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (filter.test(entry)) {
                    return true;
                }
            }
        } catch (IOException e) {
            if (logger.isErrorEnabled()) {
                logger.error(" exception processing mission package files", e);
            }
        }
        return false;
    }

    private static String getManifestContent(ZipInputStream zis, ZipEntry entry, long currentTotalBytes) throws IOException {
        final int BUFFER = 2048;
        ByteArrayOutputStream bosXml = new ByteArrayOutputStream();
        int count;
        long entryBytes = 0;
        long compressedSize = entry.getCompressedSize();
        byte[] buf = new byte[BUFFER];
        while ((count = zis.read(buf, 0, BUFFER)) != -1) {
            entryBytes += count;
            if (entryBytes > MAX_UNCOMPRESSED_ENTRY_SIZE) {
                throw new IOException("ZIP manifest entry exceeds maximum uncompressed size");
            }
            if (currentTotalBytes + entryBytes > MAX_UNCOMPRESSED_TOTAL_SIZE) {
                throw new IOException("ZIP archive exceeds maximum total uncompressed size");
            }
            if (compressedSize > 0 && entryBytes / compressedSize > MAX_COMPRESSION_RATIO) {
                throw new IOException("ZIP entry compression ratio exceeds maximum, possible zip bomb");
            }
            bosXml.write(buf, 0, count);
        }
        String manifestContent = new String(bosXml.toByteArray());
        bosXml.flush();
        bosXml.close();
        return manifestContent;
    }
}