package com.github.susom.mhealth.server.services;

/**
 * This interface represents a service that can send email.
 */
public interface Mailer {
  /**
   * Create and send a text email.
   *
   * @return true if the mail was or is guaranteed to be sent; false otherwise
   */
  boolean sendText(String from, String replyTo, String to, String cc, String bcc, String subject, String content);

  boolean sendHtml(String from, String replyTo, String to, String cc, String bcc, String subject, String content);

  boolean sendAttachment(String from, String replyTo, String to, String cc, String bcc, String subject, String content,
      byte[] attachement);
}
