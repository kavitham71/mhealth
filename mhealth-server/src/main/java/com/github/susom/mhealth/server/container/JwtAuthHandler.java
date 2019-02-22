package com.github.susom.mhealth.server.container;

import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.Metric;
import com.github.susom.mhealth.server.services.MyPartDao;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.web.RoutingContext;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Ensure a device has properly authenticated. This works by
 * verifying a JWT token passed in the Bridge-Session HTTP header.
 */
public class JwtAuthHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(JwtAuthHandler.class);
  private final JWTAuth jwt;
   private final ArrayList<String> invalidTokenCache;

  public JwtAuthHandler(JWTAuth jwt,ArrayList<String> invalidTokenCache) {
    this.jwt = jwt;
    this.invalidTokenCache = invalidTokenCache;
  }

  public void handle(RoutingContext rc) {
    String sessionToken = rc.request().getHeader("Bridge-Session");
    if (sessionToken == null) {
      rc.response().setStatusCode(401).end("Header Bridge-Session was not provided");
      return;
    }
    rc.request().pause();
    if (!invalidTokenCache.contains(sessionToken)) {
        jwt.authenticate(new JsonObject().put("jwt", sessionToken), r -> {
          Metric metric = rc.get("metric");
          if (r.succeeded()) {
            if (metric != null) {
              metric.checkpoint("auth");
            }
            String deviceRpid = r.result().principal().getString("sub");
            Boolean consented = r.result().principal().getBoolean("consented");
            rc.put("deviceRpid", deviceRpid);
            rc.put("sessionToken",sessionToken);
            rc.put("consented", consented);
            try {
              MDC.put("deviceRpid", deviceRpid);
              rc.request().resume();
              rc.next();
            } finally {
              MDC.remove("deviceRpid");
            }
          } else {
            if (metric != null) {
              metric.checkpoint("authFail");
            }
            log.warn("Session token could not be authenticated", r.cause());
            rc.response().setStatusCode(401).end("Session expired");
          }
        });
      } else {
        log.warn("Session token could not be authenticated");
        rc.response().setStatusCode(401).end("Session expired");
      }
    }
}
