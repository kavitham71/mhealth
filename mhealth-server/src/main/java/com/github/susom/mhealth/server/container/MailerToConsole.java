package com.github.susom.mhealth.server.container;

import com.github.susom.mhealth.server.services.Mailer;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the mailer interface that writes the emails to the console.
 */
public class MailerToConsole implements Mailer {
  private static final Logger log = LoggerFactory.getLogger(MailerToConsole.class);
  private String sender;

  public MailerToConsole(String sender) {
    this.sender = sender;
  }

  public boolean sendHtml(String from, String replyTo, String to, String cc, String bcc,
                          String subject, String content) {
    return sendText(from, replyTo, to, cc, bcc, subject, content, null);
  }

  public boolean sendAttachment(String from, String replyTo, String to, String cc, String bcc, String subject,
                                String content, byte[] pdf) {
    return sendText(from, replyTo, to, cc, bcc, subject, content, pdf);
  }

  public boolean sendText(String to, String cc, String bcc, String subject, String content) {
    return sendText(sender, null, to, cc, bcc, subject, content);
  }

  public boolean sendText(String from, String replyTo, String to, String cc, String bcc,
                          String subject,
                          String content) {
    return sendText(sender, null, to, cc, bcc, subject, content, null);
  }

  public boolean sendText(String from, String replyTo, String to, String cc, String bcc, String subject, String content,
                          byte[] pdf) {
    String email = null;
    try {
      email = "---------- Mail would have been sent at " + new Date() + ":\nFrom: " + from + "\nReply-To: " + replyTo
          + "\nTo: " + to + "\nCc: " + cc + "\nBcc: " + bcc + "\nSubject: " + subject + "\nContent:\n" + content
          + "\n----------";

      if (pdf != null) {
        String attach = new String(pdf);
        email = email.concat(attach);
      }
      log.debug("Email in MailerToConsole:" + email);
      return true;
    } catch (Exception e) {
      log.error("Error writing email to console: " + email, e);
      return false;
    }
  }
}
