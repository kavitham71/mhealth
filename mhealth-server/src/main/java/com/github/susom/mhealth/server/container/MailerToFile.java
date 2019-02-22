package com.github.susom.mhealth.server.container;

import com.github.susom.mhealth.server.services.Mailer;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the mailer interface that writes the emails to a local file.
 */
public class MailerToFile implements Mailer {
  private static final Logger log = LoggerFactory.getLogger(MailerToFile.class);
  private File file;

  public MailerToFile(File file) {
    this.file = file;
  }

  public boolean sendHtml(String from, String replyTo, String to, String cc, String bcc,
                          String subject, String content) {
    return sendText(from, replyTo, to, cc, bcc, subject, content);
  }

  public boolean sendAttachment(String from, String replyTo, String to, String cc, String bcc, String subject,
                                String content, byte[] pdf) {
    return sendText(from, null, to, cc, bcc, subject, content, pdf);
  }

  public boolean sendText(String from, String replyTo, String to, String cc, String bcc, String subject,
                          String content) {
    return sendText(from, null, to, cc, bcc, subject, content, null);
  }

  public boolean sendText(String from, String replyTo, String to, String cc, String bcc,
                          String subject, String content,
                          byte[] pdf) {
    FileOutputStream out = null;
    String email = null;
    try {
      email = "---------- Mail would have been sent at " + new Date() + ":\nFrom: " + from + "\nReply-To: " + replyTo
          + "\nTo: " + to + "\nCc: " + cc + "\nBcc: " + bcc + "\nSubject: " + subject + "\nContent:\n" + content
          + "\n----------";
      // don't want the binary content in email file
      /*
       * if (pdf != null) { String attach = new String(pdf); email = email.concat(attach); }
       */
      out = new FileOutputStream(file, true);
      out.write(email.getBytes());
      return true;
    } catch (Exception e) {
      log.error("Error writing email to disk: " + email, e);
      return false;
    } finally {
      if (out != null) {
        try {
          out.close();
        } catch (Exception e) {
          log.error("Error closing the email file", e);
        }
      }
    }
  }
}
