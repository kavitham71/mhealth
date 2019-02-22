package com.github.susom.mhealth.server.container;

import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.VertxUtil;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.StrictResourceHandler;
import com.github.susom.vertx.base.BadRequestException;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.Auth;
import com.github.susom.mhealth.server.services.MyPartDao.Client;
import com.github.susom.mhealth.server.services.MyPartDao.Code;
import com.github.susom.mhealth.server.services.MyPartDao.DeviceEmail;
import com.github.susom.mhealth.server.services.MyPartDao.Signup;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import com.github.susom.mhealth.server.services.Util;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.jetbrains.annotations.NotNull;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Portal for research participants at Stanford. This should allow them to
 * provision an account, verify their email, view and update their profile
 * and preferences, view and manage study consents, enable/disable data
 * collection (e.g. phone apps, IoT devices), etc.
 *
 * @author garricko
 */
public class ParticipantPortal {
  private static final Logger log = LoggerFactory.getLogger(ParticipantPortal.class);
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final Mailer mailer;
  private String portalUrl;
  private String portalEmailSender;
  private boolean centralAuth;
  /** For example: "genepool.png" -> "genepool/logo.png" */
  private Map<String, String> logoUrlToPath = new HashMap<>();

  public ParticipantPortal(Builder dbb, SecureRandom secureRandom, Mailer mailer, Config config) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.mailer = mailer;
    portalEmailSender = config.getString("portal.email.sender", "noreply@example.com");
    portalUrl = config.getStringOrThrow("portal.url");
    centralAuth = config.getBooleanOrFalse("portal.authentication");

    // Keep a list of the logo locations for each study here
    logoUrlToPath.put("default.svg", "default/logo.svg");
    logoUrlToPath.put("cardiovascular.svg", "cardiovascular/logo.svg");
    logoUrlToPath.put("genepool.png", "genepool/logo.png");
//    logoUrlToPath.put("stopwatch.png", "stopwatch/logo.png");
    logoUrlToPath.put("stream.png", "stream/logo.png");
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    router.route().handler(new MetricsHandler(secureRandom));

    // Handlers for the MyHeart Counts email verification link
    router.get("/verify/:token").handler(verifyEmail());
    router.get("/images/:logo").handler(rc -> {
      String path = logoUrlToPath.get(rc.request().getParam("logo"));
      if (path == null) {
        rc.response().setStatusCode(404).end();
      } else {
        rc.response().sendFile(path);
      }
    });

    // TODO cache/nocache handler

    if (centralAuth) {
      // Check credentials (username and password)
      router.post("/authenticate").handler(smallBodyHandler);
      router.post("/authenticate").handler(this::authenticate).failureHandler(this::fail);

      // New user sign up
      router.post("/signup").handler(smallBodyHandler);
      router.post("/signup").handler(this::signup).failureHandler(this::fail);

      // Used by the email verification end point (when they click the email link)
      router.post("/verify-token").handler(smallBodyHandler);
      router.post("/verify-token").handler(this::verifyToken).failureHandler(this::fail);
      router.post("/reset-password").handler(smallBodyHandler);
      router.post("/reset-password").handler(this::resetPassword).failureHandler(this::fail);

      // Issue a token to the study site so it knows the authenticated user
      // and may be able to do things for them
      router.post("/token").handler(rc -> {
        // Make the HTML form encoded body accessible to getFormAttribute()
        rc.request().setExpectMultipart(true);
        rc.next();
      });
      router.post("/token").handler(smallBodyHandler);
      router.post("/token").handler(this::issueToken).failureHandler(this::fail);

      // Serve static html and related resources for the login/logout client
      router.get("/*").handler(new StrictResourceHandler(vertx)
          .addDir("static/portal-auth")
          .addDir("static/assets", "**/*", "assets")
          .rename("login.html", "login")
          .rename("logout.html", "logout")
          .rename("mail.html", "mail")
      );
    }

    return router;
  }

  private void verifyToken(RoutingContext rc) {
    JsonObject json = Valid.nonNull(rc.getBodyAsJson(), "No body");
    String token = Valid.safeReq(json.getString("token"), "Invalid token");

    dbb.transactAsync(dbs -> {
      MyPartDao dao = new MyPartDao(dbs, secureRandom);

      String passwordResetToken = dao.verifySignupToken(token);
      if (passwordResetToken != null) {
        return new JsonObject().put("action", "success").put("token", passwordResetToken);
      } else {
        // TODO should cause significant clock delay outside transaction
        return new JsonObject().put("action", "error");
      }
    }, jsonResponseHandler(rc));
  }

  private void resetPassword(RoutingContext rc) {
    JsonObject json = Valid.nonNull(rc.getBodyAsJson(), "No body");
    String token = Valid.safeReq(json.getString("token"), "Invalid token");
    // TODO normalize/validate the password?
    String password = json.getString("password");

    dbb.transactAsync(dbs -> {
      MyPartDao dao = new MyPartDao(dbs, secureRandom);

      if (dao.resetPassword(token, password)) {
        return new JsonObject().put("action", "success");
      } else {
        // TODO should cause significant clock delay after transaction
        return new JsonObject().put("action", "error");
      }
    }, jsonResponseHandler(rc));
  }

  private void authenticate(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");
    String clientId = Valid.safeReq(loginJson.getString("clientId"), "Invalid clientId");

    dbb.transactAsync(dbs -> {
      MyPartDao dao = new MyPartDao(dbs, secureRandom);
      Client client = Valid.nonNull(dao.clientByClientId(clientId), "Client unknown");

      String scope = loginJson.getString("scope");

      // TODO hard-coded scope
      if (scope == null || !(scope.equals("openid") || scope.equals("openid send"))) {
        throw new BadRequestException("No scope or invalid scope");
      }

      Auth authToCheck = dao.authByEmail(loginJson.getString("email"));
      if (authToCheck != null && OpenBSDBCrypt.checkPassword(authToCheck.password,loginJson.getString("password").toCharArray())) {
        Code code = dao.createAuthCode(clientId, scope, authToCheck);

        QueryStringEncoder params = new QueryStringEncoder("");

        params.addParam("code", code.code);
        params.addParam("state", loginJson.getString("state"));

        return new JsonObject().put("action", "redirect").put("url", client.redirectUri + params);
      } else {
        return new JsonObject().put("action", "login").put("message", "Incorrect user or password");
      }
    }, jsonResponseHandler(rc));
  }

  private void signup(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");
//    String clientId = Valid.safeReq(loginJson.getString("clientId"), "Invalid clientId");

    String email = Valid.nonNullNormalized(loginJson.getString("email"), "No email");
    if (!EmailValidator.getInstance(false).isValid(email)) {
      throw new BadRequestException("Email is not valid");
    }

    VertxUtil.executeBlocking(rc.vertx(), future -> {
      try {
        String[] emailToken = new String[1];

        // Store the request with enough information to verify it later
        // from an email link
        dbb.transact(dbp -> {
          MyPartDao dao = new MyPartDao(dbp, secureRandom);
//      Client client = Valid.nonNull(dao.clientByClientId(clientId), "Client unknown");
//
//      String scope = loginJson.getString("scope");
//
//      // TODO hard-coded scope
//      if (scope == null || !(scope.equals("openid") || scope.equals("openid send"))) {
//        throw new BadRequestException("No scope or invalid scope");
//      }

          List<Signup> previous = dao.recentSignupsByEmail(email);
          if (previous.isEmpty()) {
            emailToken[0] = dao.createSignup(email);
          } else if (previous.get(0).createTime.toInstant().isBefore(Instant.now().minus(5, ChronoUnit.MINUTES))) {
            emailToken[0] = dao.createSignup(email);
          } else if (previous.get(0).createTime.toInstant().isBefore(Instant.now().minus(5, ChronoUnit.MINUTES))) {
            emailToken[0] = dao.createSignup(email);
          } else {
            throw new RuntimeException("Rate limited email for " + email);
          }
        });

        // Generate and send an email to the user with a verification link
        boolean sent = sendEmail(email, emailToken[0]);

        // Update the database to indicate we sent the mail
        dbb.transact(dbp -> {
          MyPartDao dao = new MyPartDao(dbp, secureRandom);
          dao.signupSent(emailToken[0], sent);
        });

        if (sent) {
          future.complete("sent");
        } else {
          future.fail("Couldn't send the email");
        }
      } catch (Exception e) {
        future.fail(e);
      }
    }, result -> {
      if (result.succeeded()) {
        rc.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
            .end(new JsonObject().put("action", result.result()).encode());
      } else {
        log.error("Unable to store signup request", result.cause());
        rc.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
      }
    });
  }

  private boolean sendEmail(String emailRecipient, String emailToken) {
    QueryStringEncoder params = new QueryStringEncoder("");
    params.addParam("t", emailToken);

    String sender = portalEmailSender;
    String portalUrl = this.portalUrl + "/mail" + params.toString();
    String html = "<html><body><p>To complete the signup process, click this link:</p>"
        + "<p>" + portalUrl + "</p></body></html>";
    return mailer.sendHtml(sender, null, emailRecipient, null, null, "Complete your signup", html);
  }

  private void issueToken(RoutingContext rc) {
    Valid.formAttributeEqualsShow(rc, "grant_type", "authorization_code");
    String authCode = Valid.safeFormAttributeReq(rc, "code");
    String clientId = Valid.safeFormAttributeReq(rc, "client_id");
    String clientSecret = Valid.safeFormAttributeReq(rc, "client_secret");

    dbb.transactAsync(dbs -> {
      MyPartDao dao = new MyPartDao(dbs, secureRandom);
      Code code = dao.tempAuthCodeByCode(authCode);

      if (code == null || code.expires.isBefore(Instant.now())) {
        throw new BadRequestException("Code not valid or expired");
      }

      Valid.formAttributeEqualsHide(rc, "scope", code.scope);

      Client client = dao.clientByClientId(clientId);

      if (client == null || !OpenBSDBCrypt.checkPassword(client.clientSecret,clientSecret.toCharArray())) {
        throw new BadRequestException("Client id or secret incorrect");
      }

      Valid.formAttributeEqualsHide(rc, "redirect_uri", client.redirectUri);

      return new JsonObject()
          .put("accountId", code.auth.usernameDisplay)
          .put("userDisplayName", code.auth.displayName)
          .put("scope", code.scope);
    }, jsonResponseHandler(rc));
  }

  @NotNull
  private Handler<AsyncResult<JsonObject>> jsonResponseHandler(RoutingContext rc) {
    return h -> {
      if (h.succeeded()) {
        rc.response().putHeader("content-type", "application/json").end(h.result().encode());
      } else {
        rc.fail(h.cause());
      }
    };
  }

  private void fail(RoutingContext rc) {
    if (isOrCausedBy(rc.failure(), BadRequestException.class)) {
      log.debug("Validation error", rc.failure());
      rc.response().setStatusCode(400).end(rc.failure().getMessage());
    } else {
      log.error("Unexpected error", rc.failure());
      rc.response().setStatusCode(500).end();
    }
  }

  private boolean isOrCausedBy(Throwable top, Class<? extends Throwable> type) {
    for (Throwable t : ExceptionUtils.getThrowables(top)) {
      if (type.isAssignableFrom(t.getClass())) {
        return true;
      }
    }
    return false;
  }

  /**
   * @param resourceName path to a resource in the classpath
   * @return the contents of the resource or null if it wasn't found or could not be loaded
   */
  public static String loadResource(String resourceName) {
    try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
      return in == null ? null : new Scanner(in).useDelimiter("\\Z").next();
    } catch (Exception e) {
      log.error("Unexpected error reading resource " + resourceName, e);
    }
    return null;
  }

  private String renderVerified(JsonObject studyObj) {
    String name = studyObj.getString("short_name");
    String resourceName = name + "/verifiedEmail.html";
    String html = loadResource(resourceName);
    if (html == null) {
      html = loadResource("default/verifiedEmail.html");
    }
    Map<String, String> map = new HashMap<>();
    map.put("title", studyObj.getString("display_name"));
    map.put("src", "../images/default.svg");
    if (logoUrlToPath.containsKey(name + ".svg")) {
      map.put("src", "../images/" + name + ".svg");
    } else if (logoUrlToPath.containsKey(name + ".png")) {
      map.put("src", "../images/" + name + ".png");
    }
    map.put("study",studyObj.getString("display_name"));
    return Util.resolveHtmlTemplate(html, map);
  }

  private String renderNotVerified(JsonObject studyObj) {
    String name = studyObj.getString("short_name");
    String resourceName = name + "/notVerifiedEmail.html";
    String html = loadResource(resourceName);
    if (html == null) {
      html = loadResource("default/notVerifiedEmail.html");
    }
    Map<String, String> map = new HashMap<>();
    map.put("title", studyObj.getString("display_name"));
    map.put("src", "../images/default.svg");
    if (logoUrlToPath.containsKey(name + ".svg")) {
      map.put("src", "../images/" + name + ".svg");
    } else if (logoUrlToPath.containsKey(name + ".png")) {
      map.put("src", "../images/" + name + ".png");
    }
    map.put("mail.link", "mailto:" + studyObj.getString("support_email"));
    map.put("mail", studyObj.getString("support_email"));
    return Util.resolveHtmlTemplate(html, map);
  }

  @NotNull
  private Handler<RoutingContext> verifyEmail() {
    return rc -> {
      final String token = rc.request().getParam("token");
      String[] verifiedMail = new String[1];
      String[] notVerifiedMail = new String[]{"Bad Request. Invalid Token."};
      if (!SessionKeyGenerator.validate(token)) {
        rc.response().setStatusCode(400).end("Email token is not valid");
        return;
      }

      dbb.transactAsync(dbp -> {
        DeviceEmail de = dbp.get()
            .toSelect("select device_rpid, device_description, email_recipient from"
                + " rp_device_register_request where email_token=? and email_send_time + interval '24' hour > ?")
            .argString(token).argDateNowPerDb().query(rs -> {
              DeviceEmail result = null;
              if (rs.next()) {
                result = new DeviceEmail();
                result.deviceRpid = rs.getStringOrEmpty();
                result.deciveDescription = rs.getStringOrEmpty();
                result.emailRecipient = rs.getStringOrEmpty();
              }
              return result;
            });

        if (de == null) {
          return false;
        }

        Long userId = dbp.get().toSelect("select rp_user_id from rp_user_email where email_address=?")
            .argString(de.emailRecipient.toLowerCase()).queryLongOrNull();
        // Get the study Id for the user
        Long studyId = dbp.get().toSelect("select rp_study_id from rp_device_register_request where device_rpid =?")
            .argString(de.deviceRpid).queryLongOrNull();
        //Get the study Id for genepool
        JsonObject studyObj = dbp.get().toSelect(
            "select display_name,rp_study_support_email,short_name from rp_study where rp_study_id = ?")
            .argLong(studyId).<JsonObject>query(
                (r) -> {
                  JsonObject row = null;
                  if (r.next()) {
                    row = new JsonObject();
                    row.put("display_name", r.getStringOrNull("display_name"));
                    row.put("support_email", r.getStringOrNull("rp_study_support_email"));
                    row.put("short_name", r.getStringOrNull("short_name"));
                  }
                  return row;
                });

        notVerifiedMail[0] = renderNotVerified(studyObj);

        //Now get the Verified email text
        verifiedMail[0] = renderVerified(studyObj);

        if (userId == null) {
          // Create a new user
          userId = dbp.get().toInsert("insert into rp_user (rp_user_id) values (?)").argPkSeq("rp_pk_seq")
              .insertReturningPkSeq("rp_user_id");

          dbp.get()
              .toInsert("insert into rp_user_email (rp_user_email_id, rp_user_id, email_address,"
                  + " is_primary, verify_complete_time) values (?,?,?,?,?)")
              .argPkSeq("rp_pk_seq").argLong(userId).argString(de.emailRecipient.toLowerCase()).argBoolean(true).argDateNowPerDb()
              .insert(1);

        }
       // The same user might have enrolled for another study.Therefore userId might not be null. Therefore we need to enter
        // a row in this table.if this user for this study has not been added to rp_user_in_study
        Long user = dbp.get().toSelect("select user_rpid from rp_user_in_study where rp_user_id = ? and rp_study_id = ?")
            .argLong(userId).argLong(studyId).queryLongOrNull();
        MyPartDao dao = new MyPartDao(dbp, secureRandom);
        if (user == null) {
          //this means user enrolling for the study first time
          // insert into rp_user_in_study and the history table
         dao.createUserInStudy(userId,studyId);
        }
        Boolean enabled =
            dbp.get().toSelect("select enabled from rp_user_device where device_rpid=?" + " and rp_user_id=?")
                .argString(de.deviceRpid).argLong(userId).queryBooleanOrNull();

        if (enabled == null) {
          // Add device to existing user
          dbp.get().toInsert("insert into rp_user_device (device_rpid, rp_user_id, enabled) values (?,?,?)")
              .argString(de.deviceRpid).argLong(userId).argBoolean(true).insert(1);
        } else if (!enabled) {
          dbp.get().toUpdate("update rp_user_device set enabled=? where device_rpid=? and rp_user_id=?")
              .argBoolean(true).argString(de.deviceRpid).argLong(userId).update(1);
        }

        return true;
        // int statusCode;
        // MhealthDao mhealthDao = new MhealthDao(dbp, 1L);
        // try {
        // mhealthDao.verify(verificationToken);
        // statusCode = 412;// verified
        // rc.response().sendFile("verifiedEmail.html");
        // } catch (Exception e) {
        // statusCode = 200;// not verified
        // rc.response().sendFile("notVerifiedEmail.html");
        // }
        // rc.response().setStatusCode(statusCode);
      }, result -> {
        if (result.succeeded()) {
          if (result.result()) {
            rc.response().setStatusCode(200).end(verifiedMail[0]);
          } else {
            rc.response().setStatusCode(200).end(notVerifiedMail[0]);
          }
        } else {
          log.warn("Error verifying email", result.cause());
          rc.response().setStatusCode(200).end(notVerifiedMail[0]);
        }
      });
    };
  }
}
