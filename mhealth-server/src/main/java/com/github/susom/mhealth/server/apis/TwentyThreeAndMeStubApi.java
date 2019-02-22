package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents our local implementation of an API to support functionality required for
 * supporting 23AndMe
 */

public class TwentyThreeAndMeStubApi {
  private static final Logger log = LoggerFactory.getLogger(TwentyThreeAndMeStubApi.class);
  private final SecureRandom secureRandom;
  private final Config config;

  public TwentyThreeAndMeStubApi(SecureRandom secureRandom, Config config) {
    this.secureRandom = secureRandom;
    this.config = config;
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    MetricsHandler metricsHandler =
        new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests"));
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    // These also do not currently require authentication. They are intended to
    // facilitate downloading of a user's 23andMe genetic data to our server.
    router.post("/api/v1/23andme").handler(metricsHandler);
    router.post("/api/v1/23andme").handler(smallBodyHandler);
    router.post("/api/v1/23andme").handler(twentyThreeAndMeHandler());

    router.get("/api/v1/23andme/:statusKey/status").handler(metricsHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(twentyThreeAndMeStatusHandler());

    return router;
  }

  @NotNull
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
        routingContext.response().setStatusCode(200).end("{\"status\":\"pending\",\"message\":\"Stubbed: status key started with a-z\"}");
      } else if (statusKey.matches("[A-Z].*")) {
        routingContext.response().setStatusCode(200).end("{\"status\":\"complete\",\"message\":\"Stubbed: status key started with A-Z\"}");
      } else if (statusKey.matches("[0].*")) {
        routingContext.response().setStatusCode(200).end("{\"status\":\"failed_abort\",\"message\":\"Stubbed: status key started with zero\"}");
      } else {
        routingContext.response().setStatusCode(200).end("{\"status\":\"failed_retry\",\"message\":\"Stubbed: status key started with 1-9\"}");
      }
    };
  }
}
