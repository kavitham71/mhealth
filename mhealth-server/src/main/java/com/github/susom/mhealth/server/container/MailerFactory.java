package com.github.susom.mhealth.server.container;

import com.github.susom.database.Config;
import com.github.susom.mhealth.server.services.Mailer;
import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple factory for creating and configuring a Mailer implementation based on
 * properties in a ServletContext
 */
public class MailerFactory {
  private Logger log = LoggerFactory.getLogger(MailerFactory.class);

  public Mailer create(Config config) {
    // Email mode is "production" to send real emails; missing or anything else to write them to file
    String emailModePropKey = "email.mode";
    String emailModeProduction = "production";
    // If this property is not set or does not match the current host's hostname, email will be written to file
    String productionHostPropKey = "email.production.host";
    // SMTP server to which we should send mail
    String emailServerKey = "email.server";
    // The file to dump emails into when not in production mode
    String emailFileKey = "email.file";
    String emailFileDefault = "email.log";
    // Indicate whether we will be using TLS with port 587
    String emailAuthPropKey = "email.auth";

    // Read configuration properties
    String emailMode = config.getString(emailModePropKey);
    String productionHost = config.getString(productionHostPropKey);
    String emailServer = config.getString(emailServerKey);
    String emailFile = config.getString(emailFileKey);
    boolean emailAuth = config.getBooleanOrFalse(emailAuthPropKey);

    boolean sendForReal = true;
    StringBuilder disableReasons = new StringBuilder();

    String hostname = null;
    try {
      hostname = InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      log.warn("Disabled email because hostname could not be determined", e);
      sendForReal = false;
    }

    if (!emailModeProduction.equals(emailMode)) {
      disableReasons.append("property ").append(emailModePropKey).append(" is not \"")
          .append(emailModeProduction).append("\"");
      sendForReal = false;
    }

    if (productionHost == null) {
      if (disableReasons.length() > 0) {
        disableReasons.append("; ");
      }
      disableReasons.append("property ").append(productionHostPropKey).append(" is not set");
      sendForReal = false;
    }

    if (hostname != null && productionHost != null && !productionHost.equals("*") && !hostname.equals(productionHost)) {
      if (disableReasons.length() > 0) {
        disableReasons.append("; ");
      }
      disableReasons.append("property ").append(productionHostPropKey)
          .append(" is not \"").append(hostname).append("\"");
      sendForReal = false;
    }

    if (emailServer == null) {
      if (disableReasons.length() > 0) {
        disableReasons.append("; ");
      }
      disableReasons.append("property ").append(emailServerKey).append(" is not set");
      sendForReal = false;
    }

    if (sendForReal) {
      log.info("Email will be sent via SMTP server " + emailServer + " with auth=" + emailAuth);
      return new MailerReal(emailServer, emailAuth);
    } else {
      if (emailFile == null) {
        if (log.isTraceEnabled()) {
          log.trace("Property " + emailFileKey + " was not set. Defaulting to \"" + emailFileDefault + "\"");
        }
        emailFile = emailFileDefault;
      }

      File file = new File(emailFile);
      log.info("Email will go to file '" + file.getAbsolutePath() + "' instead of sending (" + disableReasons + ")");
      return new MailerToFile(file);
    }
  }
}
