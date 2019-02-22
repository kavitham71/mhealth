package com.github.susom.mhealth.server.container;

import com.github.susom.mhealth.server.services.Mailer;
import java.util.Date;
import java.util.Properties;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the mailer interface that uses JavaMail.
 */
public class MailerReal implements Mailer {
  private static final Logger log = LoggerFactory.getLogger(MailerReal.class);
  private static final String MIME_TYPE_PDF = "application/pdf";
  private String smtpHost;
  private boolean useAuth;

  public MailerReal(String smtpHost, boolean useAuth) {
    this.smtpHost = smtpHost;
    this.useAuth = useAuth;
  }

  public boolean sendText(String from, String replyTo, String to, String cc, String bcc, String subject,
                          String content) {
    return sendMail(from, replyTo, to, cc, bcc, subject, content, false, null);
  }

  public boolean sendHtml(String from, String replyTo, String to, String cc, String bcc, String subject,
                          String content) {
    return sendMail(from, replyTo, to, cc, bcc, subject, content, true, null);
  }

  public boolean sendAttachment(String from, String replyTo, String to, String cc, String bcc, String subject,
                                String content, byte[] pdf) {
    return sendMail(from, replyTo, to, cc, bcc, subject, content, true, pdf);
  }

  public boolean sendMail(String from, String replyTo, String to, String cc, String bcc, String subject, String content,
                          boolean html, byte[] pdf) {
    try {
      Properties props = new Properties();
      if (useAuth) {
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.port", "587");
      }
      props.put("mail.smtp.host", smtpHost);
      props.put("mail.debug", "false");
      Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
        protected PasswordAuthentication getPasswordAuthentication() {
          return new PasswordAuthentication("", "");
        }
      });
      // Session session = Session.getInstance(props);
      session.setDebug(false);
      Message message = new MimeMessage(session);
      message.setFrom(new InternetAddress(from));
      if (replyTo != null && replyTo.length() > 0) {
        InternetAddress[] replyAddress = InternetAddress.parse(replyTo);
        message.setReplyTo(replyAddress);
      }
      InternetAddress[] toAddress = InternetAddress.parse(to);
      message.setRecipients(Message.RecipientType.TO, toAddress);
      if (cc != null && cc.length() > 0) {
        InternetAddress[] ccAddress = InternetAddress.parse(cc);
        message.setRecipients(Message.RecipientType.CC, ccAddress);
      }
      if (bcc != null && bcc.length() > 0) {
        InternetAddress[] bccAddress = InternetAddress.parse(bcc);
        message.setRecipients(Message.RecipientType.BCC, bccAddress);
      }
      message.setSubject(subject);
      message.setSentDate(new Date());
      if (html && pdf == null) {
        message.setContent(content, "text/html; charset=utf-8");
      } else if (html && pdf != null) {
        MimeMultipart mpart = new MimeMultipart();
        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setContent(content, "text/html; charset=utf-8");
        // add message body
        mpart.addBodyPart(textPart);
        MimeBodyPart pdfPart = new MimeBodyPart();
        DataSource source = new ByteArrayDataSource(pdf, MIME_TYPE_PDF);
        pdfPart.setDataHandler(new DataHandler(source));
        if (subject.contains("Assent")) {
          pdfPart.setFileName("assent.pdf");
        } else {
          pdfPart.setFileName("consent.pdf");
        }
        log.debug("PDF file Name:" + pdfPart.getFileName());
        mpart.addBodyPart(pdfPart);
        message.setContent(mpart);
      } else {
        message.setText(content);
      }
      Transport.send(message);
      return true;
    } catch (Exception e) {
      log.error("Unable to send email: " + "From: " + from + "\nReply-To: " + replyTo + "\nTo: " + to + "\nCc: " + cc
          + "\nBcc: " + bcc + "\nSubject: " + subject + "\nContent:\n" + content, e);
      return false;
    }
  }
}
