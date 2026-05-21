package com.bbn.marti.email;

import jakarta.mail.internet.MimeMessage;
import java.util.HashMap;
import java.util.Map;

import com.bbn.marti.config.Email;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;


public class EmailClient {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(EmailClient.class);

    // Per-call SMTP timeouts. Without these, JavaMailSenderImpl.send() blocks
    // the calling thread on socket connect/read for the OS default (minutes).
    // sendEmail is invoked synchronously from MissionServiceDefaultImpl on the
    // mission-invite path (operator-tier), so a slow/unreachable SMTP server
    // can tie up request threads (CWE-400). Tune via -Dtak.email.* properties.
    private static final String SMTP_CONNECTION_TIMEOUT_MS = System.getProperty(
            "tak.email.connectionTimeoutMs", "10000");
    private static final String SMTP_READ_TIMEOUT_MS = System.getProperty(
            "tak.email.readTimeoutMs", "30000");
    private static final String SMTP_WRITE_TIMEOUT_MS = System.getProperty(
            "tak.email.writeTimeoutMs", "30000");

    public static void sendEmail(Email config, String subject, String text, String to, String cc,
                                 HashMap<String, byte[]> attachments) {
        try {

            JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
            mailSender.setHost(config.getHost());
            mailSender.setPort(config.getPort());
            mailSender.setUsername(config.getUsername());
            mailSender.setPassword(config.getPassword());

            java.util.Properties props = mailSender.getJavaMailProperties();
            props.setProperty("mail.smtp.connectiontimeout", SMTP_CONNECTION_TIMEOUT_MS);
            props.setProperty("mail.smtp.timeout", SMTP_READ_TIMEOUT_MS);
            props.setProperty("mail.smtp.writetimeout", SMTP_WRITE_TIMEOUT_MS);
            // Also set the SSL variants so STARTTLS / SMTPS paths inherit the cap.
            props.setProperty("mail.smtps.connectiontimeout", SMTP_CONNECTION_TIMEOUT_MS);
            props.setProperty("mail.smtps.timeout", SMTP_READ_TIMEOUT_MS);
            props.setProperty("mail.smtps.writetimeout", SMTP_WRITE_TIMEOUT_MS);

            MimeMessage message = mailSender.createMimeMessage();
            message.setContent(text, "text/plain");

            MimeMessageHelper helper = new MimeMessageHelper(message, true, "utf-8");
            helper.setSubject(subject);
            helper.setText(text);
            helper.setFrom(config.getFrom());
            helper.setTo(to);

            if (cc != null) {
                helper.addCc(cc);
            }

            if (attachments != null) {
                for (Map.Entry<String, byte[]> attachment : attachments.entrySet()) {
                    helper.addAttachment(attachment.getKey(), new ByteArrayResource(attachment.getValue()));
                }
            }

            mailSender.send(message);

        } catch (Exception e) {
            logger.error("exception in sendEmail!", e);
        }
    }
}