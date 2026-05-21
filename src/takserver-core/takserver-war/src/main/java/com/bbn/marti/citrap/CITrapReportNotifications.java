package com.bbn.marti.citrap;

import java.util.List;
import java.util.NavigableSet;
import java.util.UUID;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;

import com.bbn.marti.citrap.reports.ReportType;
import com.bbn.marti.config.Citrap;
import com.bbn.marti.remote.SubmissionInterface;
import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.groups.Group;
import com.bbn.marti.remote.util.DateUtil;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.service.MissionService;

public class CITrapReportNotifications {

    private static final int STALE = 7 * 24 * 60 * 60 * 1000; // 1 week

    @Autowired
    private PersistenceStore persistenceStore;

    @Autowired
    private SubmissionInterface submission;
    
    @Autowired
    private MissionService missionService;

    // SECURITY: XML-escape attacker-controlled fields concatenated into the
    // CoT notification envelope. Report summary, callsign, uid, type are
    // derived from client-uploaded report data; without escaping a crafted
    // value can inject closing tags or new elements (CWE-91 / CWE-74).
    // package-private for unit tests; do not widen further.
    static String xmlEscape(String s) {
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

    private static String getReportNotificationCot(String senderUid, String senderCallsign, String destUid, double lon, double lat, String reportSummary, String cotType) {
        String time = DateUtil.toCotTime(System.currentTimeMillis());
        String staleTime = DateUtil.toCotTime(System.currentTimeMillis() + STALE);
        String cot = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
                + "<event version='2.0' uid='" + xmlEscape(senderUid) + "' type='" + xmlEscape(cotType) + "' "
                + "time='" + time + "' start='" +time + "' stale='" + staleTime + "' how='m-g'>"
                +		"<point lat='" + lat + "' lon='" + lon + "' hae='0.0' ce='0.0' le='0.0' />"
                + 		"<detail>"
                +           "<archive />"
                +           "<contact callsign='" +  xmlEscape(senderCallsign) + " CI Report'/>"
                + 			"<marti><dest uid='" + xmlEscape(destUid) + "'/></marti>"
                +           "<remarks>" + xmlEscape(reportSummary) + "</remarks>"
                + 		"</detail>"
                + "</event>";
        return cot;
    }

    private static String getSummary(ReportType report) {
        String summary = "CI-TRAP Report Info - ";
        summary += "Type: " + report.getType() + " - ";
        summary += "Title: " + report.getTitle() + " - ";
        summary += "Callsign: " + report.getUserCallsign() + " - ";
        summary += "User Desc: " + report.getUserDescription() + " - ";
        summary += "Date: " + report.getDateTime() + " - ";
        summary += "Date Desc: " + report.getDateTimeDescription() + " - ";
        summary += "Location Desc: " + report.getLocationDescription() + " - ";
        summary += "Event Scale: " + report.getEventScale() + " - ";
        summary += "Scale Desc: " + report.getScaleDescription() + " - ";
        summary += "Importance: " + report.getImportance();
        return summary;
    }

    // Refers to mission by name (instead of guid.) This code could be updated to support guid, but is probably not needed,
    // because the there is single named mission for each report, with the mission name == the report id.
    public void notifyNonMissionSubscribersWithinRange(
            String groupVector, ReportType report, String missionName, double lon, double lat,
            SubscriptionManagerLite subscriptionManager,
            NavigableSet<Group> groups, Citrap config) throws  Exception {

        String notificationCotType = config == null ? "a-h-G-U-C-R" : config.getNotificationCot();
        String nonsubscriberCotFilter = config == null ? "a-f%" : config.getNonsubscriberCotFilter();
        int searchRadius = config == null ? 100000 : config.getSearchRadius();
        int searchSecago = config == null ? 300 : config.getSearchSecago();

        // get everyone in range of the report
        List<String> inRange = persistenceStore.getUidsInRangeFromPoint(
                nonsubscriberCotFilter, groupVector, searchSecago, lon, lat, searchRadius);
        
        Mission reportMission = missionService.getMission(report.getId(), groupVector);

        // get everyone subscribed to the top level mission
        List<String> missionSubscribers = subscriptionManager.getMissionSubscriptions(reportMission.getGuidAsUUID(), true);

        String senderUid = UUID.randomUUID().toString();
        // iterate over users in range who are not subscribed to the top level mission
        for (String nonSubscriber : CollectionUtils.subtract(inRange, missionSubscribers)) {
            // notify users of new report
            submission.submitCot(
                    getReportNotificationCot(senderUid, report.getUserCallsign(), nonSubscriber, lon, lat, getSummary(report), notificationCotType),
                    groups);
        }
    }
}
