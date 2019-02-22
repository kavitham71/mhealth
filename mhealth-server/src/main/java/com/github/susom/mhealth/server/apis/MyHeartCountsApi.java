package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.Database;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.container.AuthorizationHandler;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.mhealth.server.container.JwtAuthHandler;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.mhealth.server.services.DeviceApp;
import com.github.susom.mhealth.server.services.MhealthDao;
import com.github.susom.mhealth.server.services.SchedulePlan;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import com.github.susom.mhealth.server.services.SharingScope;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.function.Supplier;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.jetbrains.annotations.NotNull;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class represents our local implementation of an API to support functionality required by the
 * MyHeart Counts iOS app. The intent is to be compatible enough that the Sage BridgeSDK will work
 * with few modifications.
 */
public class MyHeartCountsApi {
  private static final Logger log = LoggerFactory.getLogger(MyHeartCountsApi.class);
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final JWTAuth jwt;
  private final Config config;
  private final String portalApiHost;
  private final Integer portalApiPort;
  private final String portalApiContext;
  public final TwentyThreeAndMeApi twentyThreeAndMe;
  private final String externalUrl;
  private final HashMap<String,Long> studyIdMap;// A map from study short name to an id.
  private  Long lastUpdateSeq;//for the session token
  private ArrayList<String> invalidTokenCache; //session tokens invalidated before their expiry

  public MyHeartCountsApi(Builder dbb, SecureRandom secureRandom, JWTAuth jwt, Config config, Vertx vertx,
      TwentyThreeAndMeApi twentyThreeAndMeApi) {
    this.dbb = dbb;
    this.studyIdMap = new HashMap<>();
    this.secureRandom = secureRandom;
    this.jwt = jwt;
    this.config = config;
    portalApiHost = config.getString("portal.api.host", "localhost");
    portalApiPort = config.getInteger("portal.api.port", 8002);
    portalApiContext = "/" + config.getString("portal.api.context", "server");
    externalUrl = config.getString("proxy.forwarded.proto", "https") + "://"
        + config.getString("proxy.forwarded.host", "localhost");
    twentyThreeAndMe = twentyThreeAndMeApi;
    this.lastUpdateSeq = 0L;
    this.invalidTokenCache = new ArrayList<>();
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    MetricsHandler metricsHandler =
        new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests"));
   StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);
    // vertx.setPeriodic(600000L, (id) -> twentyThreeAndMeDownloadHandler(vertx));

    // These calls do not require authentication
    router.post("/api/v1/auth/signUp").handler(metricsHandler);
    router.post("/api/v1/auth/signUp").handler(smallBodyHandler);
    router.post("/api/v1/auth/signUp").handler(signUpHandler(vertx));

    router.post("/api/v1/auth/resendEmailVerification").handler(metricsHandler);
    router.post("/api/v1/auth/resendEmailVerification").handler(smallBodyHandler);
    router.post("/api/v1/auth/resendEmailVerification").handler(resendEmailHandler(vertx));

    router.post("/api/v1/auth/signIn").handler(metricsHandler);
    router.post("/api/v1/auth/signIn").handler(smallBodyHandler);
    router.post("/api/v1/auth/signIn").handler(signInHandler(vertx));

    // These also do not currently require authentication, and are temporarily
    // provided here for LifeMap testing purposes.
    /*router.post("/api/v1/23andme").handler(authenticationHandler);
    router.post("/api/v1/23andme").handler(metricsHandler);
    router.post("/api/v1/23andme").handler(smallBodyHandler);
    router.post("/api/v1/23andme").handler(twentyThreeAndMeHandler());
    
    router.get("/api/v1/23andme/:statusKey/status").handler(metricsHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(twentyThreeAndMeStatusHandler());*/

    /*
     * router.route(HttpMethod.GET, "/api/v1/auth/signOut") .handler(routingContext ->
     * routingContext.request().bodyHandler(body -> { log.debug("Responding to request: " +
     * routingContext.request().uri() + "\n" + routingContext.request().headers().entries() + "\n");
     * 
     * routingContext.response().setStatusCode(200).end("{\"status\":\"SignedOut\"}"); }));
     */

    // Use cryptographic, stateless sessions
    JwtAuthHandler authenticationHandler = new JwtAuthHandler(jwt,invalidTokenCache);
    AuthorizationHandler authorizationHandler = new AuthorizationHandler();

    // File uploads will allow large bodies
   StrictBodyHandler bigBodyHandler = new StrictBodyHandler(4000000);

    router.post("/api/v1/consent").handler(authenticationHandler);
    router.post("/api/v1/consent").handler(metricsHandler);
    router.post("/api/v1/consent").handler(smallBodyHandler);
    router.post("/api/v1/consent").handler(consentHandler(vertx));

    router.get("/api/v1/auth/withdraw").handler(authenticationHandler);
    router.get("/api/v1/auth/withdraw").handler(authorizationHandler);
    router.get("/api/v1/auth/withdraw").handler(metricsHandler);
    router.get("/api/v1/auth/withdraw").handler(smallBodyHandler);
    router.get("/api/v1/auth/withdraw").handler(withdrawHandler(vertx));

    router.post("/api/v1/consent/dataSharing").handler(authenticationHandler);
    router.post("/api/v1/consent/dataSharing").handler(authorizationHandler);
    router.post("/api/v1/consent/dataSharing").handler(metricsHandler);
    router.post("/api/v1/consent/dataSharing").handler(smallBodyHandler);
    router.post("/api/v1/consent/dataSharing").handler(dataSharingHandler(vertx));

    /*
     * router.post("/api/v1/profile").handler(authenticationHandler);
     * router.post("/api/v1/profile").handler(metricsHandler);
     * router.post("/api/v1/profile").handler(smallBodyHandler);
     * router.post("/api/v1/profile").handler(routingContext -> { // TODO implement (or remove?)
     * this routingContext.response().putHeader("content-type", "application/json") .end(
     * "{\"message\":\"Profile updated.\"}"); });
     */

    /*
     * router.get("/api/v1/consent").handler(authenticationHandler);
     * router.get("/api/v1/consent").handler(metricsHandler);
     * router.get("/api/v1/consent").handler(routingContext -> // TODO implement (or remove?) this
     * routingContext.response().setStatusCode(201) .putHeader("content-type", "application/json")
     * .end("{\"message\":\"User Consented.\"}") );
     */
    router.get("/api/v1/schedules").handler(authenticationHandler);
    router.get("/api/v1/schedules").handler(authorizationHandler);
    router.get("/api/v1/schedules").handler(metricsHandler);
    router.get("/api/v1/schedules").handler(routingContext -> routingContext.response().setStatusCode(200)
        .putHeader("content-type", "application/json").end(new JsonObject().put("items", new ArrayList<SchedulePlan>())
            .put("total", 0L).put("type", "ResourceList").encodePrettily()));

    router.post("/api/v1/upload").handler(authenticationHandler);
    router.post("/api/v1/upload").handler(authorizationHandler);
    router.post("/api/v1/upload").handler(metricsHandler);
    router.post("/api/v1/upload").handler(smallBodyHandler);
    router.post("/api/v1/upload").handler(createUploadHandler());

    router.put("/api/v1/upload/:id").handler(authenticationHandler);
    router.put("/api/v1/upload/:id").handler(authorizationHandler);
    router.put("/api/v1/upload/:id").handler(metricsHandler);
    router.put("/api/v1/upload/:id").handler(bigBodyHandler);
    router.put("/api/v1/upload/:id").handler(uploadHandler());

    router.post("/api/v1/upload/:id/complete").handler(authenticationHandler);
    router.post("/api/v1/upload/:id/complete").handler(authorizationHandler);
    router.post("/api/v1/upload/:id/complete").handler(metricsHandler);
    router.post("/api/v1/upload/:id/complete").handler(smallBodyHandler);
    router.post("/api/v1/upload/:id/complete").handler(uploadCompleteHandler());

    router.get("/api/v1/upload/:id/status").handler(authenticationHandler);
    router.get("/api/v1/upload/:id/status").handler(authorizationHandler);
    router.get("/api/v1/upload/:id/status").handler(metricsHandler);
    router.get("/api/v1/upload/:id/status").handler(uploadStatusHandler());

    // These also do not currently require authentication, and are temporarily
    // provided here for LifeMap testing purposes.
    router.post("/api/v1/23andme").handler(authenticationHandler);
    router.post("/api/v1/23andme").handler(authorizationHandler);
    router.post("/api/v1/23andme").handler(metricsHandler);
    router.post("/api/v1/23andme").handler(smallBodyHandler);
    router.post("/api/v1/23andme").handler(twentyThreeAndMe.twentyThreeAndMeHandler(vertx));

    router.get("/api/v1/23andme/:statusKey/status").handler(authenticationHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(authorizationHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(metricsHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(twentyThreeAndMe.twentyThreeAndMeStatusHandler());

    return router;
  }

  /* @NotNull
  private Handler<RoutingContext> twentyThreeAndMeHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String userId = request.getString("user");
      String profileId = request.getString("profile");
      String bToken = request.getString("token");
      String rToken = request.getString("refreshToken");
  
      if (userId == null || !userId.matches("[a-zA-Z0-9]{1,80}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("User is not valid");
        log.error("User is not valid: " + userId);
        return;
      }
  
      if (profileId == null || !profileId.matches("[a-zA-Z0-9_]{1,80}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Profile is not valid");
        log.error("Profile is not valid: " + profileId);
        return;
      }
  
      if (bToken == null || !bToken.matches("[a-zA-Z0-9]{1,4000}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Bearer Token is not valid");
        log.error("Bearer Token is not valid");
        return;
      }
  
      if (rToken == null || !rToken.matches("[a-zA-Z0-9]{1,4000}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Refresh Token is not valid");
        log.error("Refresh Token is not valid");
        return;
      }
  
      String statusKey = new SessionKeyGenerator(secureRandom).create();
      routingContext.response().setStatusCode(200).end("{\"statusKey\":\"" + statusKey + "\"}");
    };
  }
  
  @NotNull
  private Handler<RoutingContext> twentyThreeAndMeStatusHandler() {
    return routingContext -> {
      String statusKey = routingContext.request().getParam("statusKey");
  
      if (statusKey == null || !statusKey.matches("[a-zA-Z0-9]{1,100}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Status key is not valid");
        log.error("Status key is not valid: " + statusKey);
        return;
      }
  
      if (statusKey.matches("[a-z].*")) {
        routingContext.response().setStatusCode(200).end(
            "{\"status\":\"pending\",\"message\":\"Stubbed: status key started with a-z\"}");
      } else if (statusKey.matches("[A-Z].*")) {
        routingContext.response().setStatusCode(200).end(
            "{\"status\":\"complete\",\"message\":\"Stubbed: status key started with A-Z\"}");
      } else if (statusKey.matches("[0].*")) {
        routingContext.response().setStatusCode(200).end(
            "{\"status\":\"failed_abort\",\"message\":\"Stubbed: status key started with zero\"}");
      } else {
        routingContext.response().setStatusCode(200).end(
            "{\"status\":\"failed_retry\",\"message\":\"Stubbed: status key started with 1-9\"}");
      }
    };
  }*/

  @NotNull
  private Handler<RoutingContext> uploadCompleteHandler() {
    return routingContext -> {
      String id = routingContext.request().getParam("id");

      // TODO validate id
      if (!SessionKeyGenerator.validate(id)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Upload token is not valid");
        log.error("Upload token is not valid. Id: " + id);
        return;
      }

      // Client calls this on server when the upload is complete
      // So we need to set the complete time during this call
      dbb.transactAsync(dbp -> {
        Long fileUploadId = dbp.get()
            .toSelect(
                "select mh_file_upload_id from mh_file_upload where" + " upload_token=? and completed_time is null")
            .argString(id).queryLongOrNull();
        dbp.get().toUpdate("update mh_file_upload set completed_time=? where mh_file_upload_id=?").argDateNowPerDb()
            .argLong(fileUploadId).update(1);

        return null;
      } , result -> {
        if (result.succeeded()) {
          routingContext.response().setStatusCode(200).end();
        } else {
          log.debug("Could not mark upload complete", result.cause());
          routingContext.response().setStatusCode(500).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> uploadStatusHandler() {
    return routingContext -> {
      String id = routingContext.request().getParam("id");

      dbb.transactAsync(dbp -> {
        return dbp.get().toSelect("select completed_time from mh_file_upload where upload_token=?").argString(id)
            .queryDateOrNull();
      } , result -> {
        if (result.succeeded() && result.result() != null) {
          routingContext.response().setStatusCode(200).end("{\"status\":\"succeeded\"}");
        } else {
          routingContext.response().setStatusCode(200).end("{\"status\":\"validation_failed\"}");
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> uploadHandler() {
    return routingContext -> {
      String id = routingContext.request().getParam("id");
      String deviceRpid = routingContext.get("deviceRpid");
      // TODO validate id
      if (!SessionKeyGenerator.validate(id)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Upload token is not valid");
        log.error("Upload token is not valid. Id:  " + id);
        return;
      }
      dbb.transactAsync(dbp -> {
        String userAgent = routingContext.request().getHeader("User-Agent");
        if (userAgent == null) {
          userAgent = "";
        }
        String md5 = DigestUtils.md5Hex(userAgent);
        // Check if agent_id exists
        Long agentId = dbp.get().toSelect("select mh_user_agent_id from mh_user_agent where user_agent_md5=?")
            .argString(md5).queryLongOrNull();
        if (agentId == null) {
          Long studyId = dbp.get().toSelect("select mh_scoper_id from mh_device_app where device_rpid = ?")
              .argString(deviceRpid).queryLongOrNull();
          agentId = dbp.get().toInsert(
              "insert into mh_user_agent (mh_user_agent_id,mh_scoper_id,user_agent_md5,user_agent_str) values (:pk,?,?,?)")
              .argPkSeq(":pk", "mh_user_agent_id_pk_seq")
              .argLong(studyId).argString(md5).argString(userAgent)
              .insertReturningPkSeq("mh_user_agent_id");
        }
        return agentId;
      } , result1 -> {

        if (result1.succeeded()) {

          dbb.transactAsync(dbp -> {
            Long fileUploadId = dbp.get().toSelect("select mh_file_upload_id from mh_file_upload where"
                + " upload_token=? and completed_time is null").argString(id).queryLongOrNull();

            dbp.get().toInsert("insert into mh_file_upload_content (mh_file_upload_id, content) values (?,?)")
                .argLong(fileUploadId).argBlobBytes(routingContext.getBody().getBytes()).insert(1);

            // update the mh_device_app_id and the user_agent_id in the mh_file_upload
            // get mh_device_app_id for device_rpid from mh_device_app

            Long appId = dbp.get().toSelect("select mh_device_app_id from mh_device_app where device_rpid = ?")
                .argString(deviceRpid).queryLongOrNull();

            dbp.get().toUpdate(
                "update mh_file_upload set mh_device_app_id=?, device_app_user_agent_id =? where mh_file_upload_id=?")
                .argLong(appId)
                .argLong(result1.result()).argLong(fileUploadId).update(1);

            return null;
          } , result2 -> {
            if (result2.succeeded()) {
              routingContext.response().setStatusCode(200).end();
            } else {
              log.warn("Failed to upload", result2.cause());
              routingContext.response().setStatusCode(500).end();
            }
          });
        } else {
          //Error trying to get agent_id
          log.error("Exception while getting userAgent", result1.cause());
          routingContext.response().setStatusCode(500).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> createUploadHandler() {
    return routingContext -> {
      String deviceRpid = routingContext.get("deviceRpid");
      JsonObject jsnObj = routingContext.getBodyAsJson();
      String contentMd5 = Valid.nonNull(jsnObj.getString("contentMd5"),"contentMd5 cannot be null");
      Long contentLength = (long) Valid.nonNull(jsnObj.getInteger("contentLength"),"contentLength cannot be null");
      final String id = new SessionKeyGenerator(secureRandom).create();

      dbb.transactAsync(dbp -> {
        Long studyId = dbp.get().toSelect("select mh_scoper_id from mh_device_app where device_rpid = ?")
            .argString(deviceRpid).queryLongOrNull();
        dbp.get().toInsert("insert into mh_file_upload (mh_file_upload_id, mh_scoper_id, mh_device_app_id,"
            + "upload_token, requested_time,content_md5,content_bytes) values (?,?,(select mh_device_app_id from mh_device_app where device_rpid=?),?,?,?,?)")
            .argPkSeq("mh_pk_seq").argLong(studyId).argString(deviceRpid).argString(id).argDateNowPerDb()
            .argString(contentMd5).argLong(contentLength)
            .insert(1);

        return null;
      } , result -> {
        if (result.succeeded()) {
          UploadSession response = new UploadSession();

          response.setId(id);
          // Might want to optionally check the x-forwarded-host and x-forwarded-proto headers instead
          response.setUrl(externalUrl + routingContext.request().uri() + '/' + id);
          response.setExpires("2099-01-01T12:00:00.000Z");
          response.setType("UploadSession");

          routingContext.response().setStatusCode(201)
              .putHeader("content-type", "application/json").end(Json.encode(response));
        } else {
          log.warn("Failed to create upload", result.cause());
          routingContext.response().setStatusCode(500).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> consentHandler(Vertx vertx) {
    return routingContext -> {
      String deviceRpid = routingContext.get("deviceRpid");
      JsonObject jsnObj = routingContext.getBodyAsJson();
      jsnObj.put("deviceRpid", deviceRpid);
      HttpClient client = vertx.createHttpClient();
      String json = jsnObj.toString();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/createConsent", response -> {
        if (response.statusCode() == 202) {
          routingContext.response().setStatusCode(201); // User consented
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"message\":\"Consent to research has been recorded.\"}");
        } else {
          routingContext.response().setStatusCode(400); // Error in creating consent
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"message\":\"Consent to research has not been recorded.\"}");
        }
      }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .putHeader("Content-Length", Integer.toString(json.length())).end(json);
    };
  }

  @NotNull
  private Handler<RoutingContext> withdrawHandler(Vertx vertx) {
    return routingContext -> {
      String deviceRpid = routingContext.get("deviceRpid");
      String sessionToken = routingContext.get("sessionToken");
      JsonObject jsnObj = new JsonObject();
      jsnObj.put("deviceRpid", deviceRpid);
      HttpClient client = vertx.createHttpClient();
      String json = jsnObj.toString();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/auth/withdraw", response -> {
        if (response.statusCode() == 202) {
          dbb.transactAsync(dbp -> {
            //add the session token to the invalid_token table
            Long updateSeq = dbp.get().toSelect("select max(update_sequence) from mh_invalid_session_token").queryLongOrZero();
            //add the token to invalid token table
            dbp.get().toInsert("insert into mh_invalid_session_token(mh_session_token,update_time,update_sequence) values(?,?,?)")
                .argClobString(sessionToken).argDateNowPerDb().argLong(updateSeq + 1).insert(1);
            updateInvalidTokenCache(dbp);
            return null;
          } , result -> {
            if (result.succeeded()) {
              routingContext.response().setStatusCode(200); // User SignedOut
              routingContext.response().putHeader("content-type", "application/json").end(
                  "{\"status\":\"Withdrawn from the study.\"}");
            } else {
              routingContext.response().setStatusCode(500); // Error in SignOut
              routingContext.response().putHeader("content-type", "application/json")
                  .end("{\"status\":\" Not Withdrawn from the study.\"}");
            }
          });

        } else {
          routingContext.response().setStatusCode(500); // Error in SignOut
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"status\":\" Not Withdrawn from the study.\"}");
        }
      }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .putHeader("Content-Length", Integer.toString(json.length())).end(json);
    };
  }

  @NotNull
  private Handler<RoutingContext> dataSharingHandler(Vertx vertx) {
    return routingContext -> {
      String deviceRpid = routingContext.get("deviceRpid");
      JsonObject jsnObj = routingContext.getBodyAsJson();
      jsnObj.put("deviceRpid", deviceRpid);
      HttpClient client = vertx.createHttpClient();
      String json = jsnObj.toString();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/dataSharing", response -> {
        if (response.statusCode() == 202) {
          routingContext.response().setStatusCode(200); // changed data sharing
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"message\":\"Data sharing has been changed..\"}");
        } else if (response.statusCode() == 400) {
          routingContext.response().setStatusCode(400); // Invalid Scope
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"message\":\"Invalid Scope.\"}");
        } else {
          routingContext.response().setStatusCode(500); // Error in changing dataSharing
          routingContext.response().putHeader("content-type", "application/json")
              .end("{\"message\":\"Data sharing could not be changed.\"}");
        }
      }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .putHeader("Content-Length", Integer.toString(json.length())).end(json);
      log.debug("Send response code " + routingContext.response().getStatusCode());
    };
  }

  @NotNull
  private Handler<RoutingContext> signInHandler(final Vertx vertx) {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String deviceRpid = Valid.nonNull(request.getString("username"),"username cannot be null");
      String password = Valid.nonNull(request.getString("password"),"password cannot be null");
      String study = Valid.nonNull(request.getString("study"), "study cannot be null");

      // TODO validate username/password
      if (!SessionKeyGenerator.validate(deviceRpid)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device Id is not valid");
        log.error("Device Id  is not valid. DeviceId:  " + deviceRpid);
        return;
      }
      if (!(password.length() == 32) || !(StringUtils.isAlphanumeric(password))) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Password is not valid");
        log.error("Password is not valid");
        return;
      }

      dbb.transactAsync(dbp -> {
        // Verify the device's credentials first
        return dbp.get().toSelect("select app_key from mh_device_app where mh_scoper_id=? and device_rpid=?")
            .argLong(getStudyId(study, dbp)).argString(deviceRpid).queryStringOrNull();
      } , result -> {
        if (result.succeeded()) {
          String appKey = result.result();

          if (appKey == null || !OpenBSDBCrypt.checkPassword(appKey, password.toCharArray())) {
            routingContext.response().setStatusCode(400).end("Credentials missing or incorrect.");
            return;
          }

          //String sessionToken = jwt.generateToken(new JsonObject().put("sub", deviceRpid),
          // new JWTOptions().setExpiresInSeconds(60 * 60 * 24L));

          // Now make sure the portal currently allows this device to be used
          HttpClient client = vertx.createHttpClient();
          client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/login", response -> response
              .bodyHandler(registerBody -> {
                if (response.statusCode() == 202) {
                  String bodyString = registerBody.toString();
                  JsonObject resp = new JsonObject(bodyString);
                  Boolean dataSharing = resp.getBoolean("dataSharing");
                  Long userRpid = resp.getLong("user_rpid");
                  // set up the mh_user_profile if not already set
                  dbb.transactAsync(dbp -> {
                MhealthDao mhealthDao = new MhealthDao(dbp, getStudyId(study,dbp));

                    Long mhUserProfileId = mhealthDao.getMhUserProfileId(userRpid);

                    if (mhUserProfileId == null) {
                      mhUserProfileId = mhealthDao.createMhUserProfile(userRpid);
                    }

                    // update mh_device_app with the mh_user_profile_id
                    mhealthDao.updateMhDeviceApp(deviceRpid, mhUserProfileId);
                    return null;
                  }, result2 -> {
                    if (result2.succeeded()) {
                      String sessionToken = jwt.generateToken(new JsonObject().put("sub", deviceRpid).put("consented",
                          true),
                          new JWTOptions().setExpiresInSeconds(60 * 60 * 24));
                      routingContext.response().setStatusCode(200).putHeader("content-type", "application/json").end(
                          new JsonObject().put("authenticated", true).put("consented", true).put("sessionToken",
                              sessionToken)
                              .put("dataSharing", dataSharing).put("type", "UserSessionInfo").encodePrettily());
                    } else {
                      log.error("Error setting up the user profile", result2.cause());
                      routingContext.response().setStatusCode(500).end();
                    }
                  });
                } else if (response.statusCode() == 412) {
                  String sessionToken = jwt.generateToken(new JsonObject().put("sub", deviceRpid).put("consented", false),
                      new JWTOptions().setExpiresInSeconds(60 * 60 * 24));
                  routingContext.response().setStatusCode(412).putHeader("content-type", "application/json")
                      .end(new JsonObject().put("authenticated", true).put("consented", false)
                          .put("sessionToken", sessionToken).put("dataSharing", SharingScope.NO_SHARING.getLabel())
                          .put("type", "UserSessionInfo").encodePrettily());
                } else if (response.statusCode() == 420) {
                  routingContext.response().setStatusCode(403).putHeader("content-type", "application/json")
                      .end("{\"message\":\"User left the study. Re-enroll the user\"}");
                } else if (response.statusCode() == 401) {
                  log.error("Bad response code from portal: " + response.statusCode() + " " + response.statusMessage());
                  routingContext.response().setStatusCode(403).putHeader("content-type", "application/json")
                      .end("{\"message\":\"Device not verified or no longer allowed.\"}");
                }
              })).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
              .end(new JsonObject().put("device", deviceRpid).encodePrettily());
        } else {
          log.warn("Error checking device credentials", result.cause());
          routingContext.response().setStatusCode(400).end("{\"message\":\"Credentials missing or incorrect.\"}");
          return;
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> resendEmailHandler(final Vertx vertx) {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String deviceRpid = Valid.nonNull(request.getString("username"), "username cannot be null");
      String password = Valid.nonNull(request.getString("password"),"password cannot be null");
      String study = Valid.nonNull(request.getString("study"),"study cannnot be null");
      String email = Valid.nonNull(request.getString("email"), "email cannot be null");

      if (!SessionKeyGenerator.validate(deviceRpid)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device Id is not valid");
        log.error("Device Id is not valid. DeviceId:  " + deviceRpid);
        return;
      }
      if (!(password.length() == 32) || !(StringUtils.isAlphanumeric(password))) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Password is not valid");
        log.error("Password is not valid");
        return;
      }

      if (!EmailValidator.getInstance(false).isValid(email)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Email address is not valid");
        log.error("Email address is not valid. Email: " + email);
        return;
      }

      dbb.transactAsync(dbp -> {
        // Verify the device's credentials first
        return dbp.get().toSelect("select app_key from mh_device_app where mh_scoper_id=?" + " and device_rpid=?")
            .argLong(getStudyId(study,dbp)).argString(deviceRpid).queryStringOrNull();
      } , result -> {
        if (result.succeeded()) {
          String appKey = result.result();
          if (appKey == null || !OpenBSDBCrypt.checkPassword(appKey, password.toCharArray())) {
            routingContext.response().setStatusCode(400).end("Credentials missing or incorrect.");
            return;
          }

          HttpClient client = vertx.createHttpClient();
          Integer length = request.toString().length();
          client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/resendEmailVerification",
              response -> response.bodyHandler(registerBody -> {
                if (response.statusCode() == 202) {
                  routingContext.response().setStatusCode(200); // email sent

                  routingContext.response().putHeader("content-type", "application/json")
                      .end("{\"message\":\"If registered with the study, we'll email you instructions"
                          + " on how to verify your account.\"}");
                } else {
                  routingContext.response().setStatusCode(500).putHeader("content-type", "application/json")
                      .end("{\"message\":\"Error in resending the mail.\"}");
                }
              })).setChunked(false).putHeader("Content-Length", length.toString())
              .exceptionHandler(routingContext::fail)
              .write(request.toString()).putHeader("content-type", "application/json").end();
        } else {
          log.warn("Error checking device credential", result.cause());
          routingContext.response().setStatusCode(400).end("Credentials missing or incorrect.");
          return;
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> signUpHandler(Vertx vertx) {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String password = Valid.nonNull(request.getString("password"), "password cannot be null");
      String email = Valid.nonNull(request.getString("email"),"email cannot be null");
      String study = Valid.nonNull(request.getString("study"),"study cannot be null");

      String description;

      description = (study.equals("cardiovascular")) ? "MyHeart Counts iOS App" : "GenePool iOS App";

      if (!EmailValidator.getInstance(false).isValid(email)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Email address is not valid");
        log.error("Email address is not valid. Email: " + email);
        return;
      }
      // TODO validate username/password
      if (!(password.length() == 32) || !(StringUtils.isAlphanumeric(password))) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Password is not valid");
        log.error("Password is not valid");
        return;
      }
      String sessionToken = routingContext.request().getHeader("Bridge-Session");

      HttpClient client = vertx.createHttpClient();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/register", response -> response.bodyHandler(
          registerBody -> {
            if (response.statusCode() == 202) {
              JsonObject registerJson = new JsonObject(registerBody.toString());
              String deviceRpid = Valid.nonNull(registerJson.getString("device"), "device cannot be null");
              if (!SessionKeyGenerator.validate(deviceRpid)) {
                routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
                    .end("Device Id is not valid");
                log.error("Device Id is not valid. DeviceId:  " + deviceRpid);
                return;
              }

              dbb.transactAsync(dbp -> {
                // TODO store user agent and ip
                DeviceApp deviceApp = new DeviceApp();
                deviceApp.setDeviceRpid(deviceRpid);
                byte[] salt = new byte[16];
                secureRandom.nextBytes(salt);
                deviceApp.setAppKey(OpenBSDBCrypt.generate(password.toCharArray(),salt,13));
                deviceApp.setAppKeyType("password_bcrypted");
            MhealthDao mhealthDao = new MhealthDao(dbp, getStudyId(study,dbp));
                mhealthDao.createDeviceApp(deviceApp);

                return null;
              }, result -> {
                if (result.succeeded()) {
                  routingContext.response().setStatusCode(201).putHeader("content-type", "application/json")
                      .end("{\"message\":\"Signed up.\",\"username\":\"" + deviceRpid + "\"}");
                } else {
                  log.error("Exception during Signup", result.cause());
                  routingContext.response().setStatusCode(500).putHeader("content-type", "application/json")
                  .end("{\"message\":\" Not Signed up.\"}");
                }
              });

            } else {
              log.error("Bad response code from portal: " + response.statusCode() + " " + response.statusMessage());
          String message = (response.statusMessage() == null ? "Not Signed up" : response.statusMessage());
              routingContext.response().setStatusCode(500)
                  .putHeader("content-type", "application/json")
              .end("{\"message\":\"" + message + "\"}");
            }
          })).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .end(new JsonObject().put("email", email).put("description", description)
              .put("study", study).put("sageSession", sessionToken).encodePrettily());
    };
  }

  private Long getStudyId(String shortName, Supplier<Database> dbb) {
    Long result;
    if (studyIdMap.containsKey(shortName)) {
      result = studyIdMap.get(shortName);
    } else { // the study is not already mapped
      result = dbb.get().toSelect("select mh_scoper_id from mh_scoper where short_name = ?")
          .argString(shortName).queryLongOrNull();
      studyIdMap.put(shortName,result);
      Valid.nonNull(result,"Unknown Study");
    }
    return result;
  }

  public void updateInvalidTokenCache(Supplier<Database>  dbb) {
    //get the invalid tokens that were added after the lastUpdateSeq
    dbb.get().toSelect("select mh_session_token from mh_invalid_session_token where update_sequence > ?")
        .argLong(lastUpdateSeq).queryMany(r -> {
        invalidTokenCache.add(r.getClobStringOrEmpty());
      return null;
    });
    //update the lastUpdateSeq
    lastUpdateSeq = dbb.get().toSelect("select max(update_sequence) from mh_invalid_session_token").queryLongOrZero();
  }

  public void loadInvalidTokenCache(Handler<AsyncResult<String>> resultHandler) {
    // assigning the mh_upload_sequence to the uploaded files
    dbb.transactAsync(dbp -> {
      //Delete all the invalid tokens that are expired.Any token which has been in the table for
      // more than a day has expired
      dbp.get().toDelete("delete from mh_invalid_session_token where update_time + interval '24' hour <= ?").argDateNowPerDb()
          .update();
      //clear the cache
      invalidTokenCache.clear();
      lastUpdateSeq = dbp.get().toSelect("select max(update_sequence) from mh_invalid_session_token").queryLongOrZero();
      dbp.get().toSelect("select mh_session_token from mh_invalid_session_token")
          .queryMany(r -> {
            invalidTokenCache.add(r.getClobStringOrEmpty());
            return null;
          });
      return null;
    } , result -> {
      if (result.succeeded()) {
        log.debug("Successfully loaded the invalid token cache ");
        resultHandler.handle(Future.succeededFuture("loadInvalidTokenCache ran successfully"));
      }
      if (result.failed()) {
        log.debug("Failed to load invalid token cache ", result.cause());
        resultHandler.handle(Future.failedFuture("Failed to load invalid token cache"));
      }
    });
  }
}
