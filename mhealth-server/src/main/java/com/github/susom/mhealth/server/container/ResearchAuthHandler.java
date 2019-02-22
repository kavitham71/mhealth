package com.github.susom.mhealth.server.container;

import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.Metric;
import com.github.susom.vertx.base.Valid;
import com.github.susom.mhealth.server.services.MhealthDao;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Ensure a researcher has properly authenticated. This works by
 * verifying a token passed in the Authorization HTTP header.
 */
public class ResearchAuthHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(ResearchAuthHandler.class);
  private static final Pattern AUTHORIZATION_HEADER = Pattern.compile("Bearer [a-zA-Z0-9]{32,512}");
  private final Builder dbb;

  public ResearchAuthHandler(Builder dbb) {
    this.dbb = dbb;
  }

  public void handle(RoutingContext rc) {
    String tokenHeader = rc.request().getHeader("Authorization");
    Valid.matchesReq(tokenHeader, AUTHORIZATION_HEADER, "Header 'Authorization' must match 'Bearer <token>'");
    String token = tokenHeader.substring(7);

    rc.request().pause();

    // Access the database to validate the token
    dbb.transactAsync(dbp -> {
      return new MhealthDao(dbp, -1).identityByToken(token);
    } , result -> {
      Metric metric = rc.get("metric");
      if (result.succeeded() && result.result() != null) {
        if (metric != null) {
          metric.checkpoint("auth");
        }
        rc.put("studyId", result.result().studyId);
        rc.put("sunetId", result.result().username);
        rc.put("orgId", result.result().orgId);
        try {
          MDC.put("studyId", result.result().studyId.toString());
          MDC.put("userId", result.result().username);
          rc.request().resume();
          rc.next();
        } finally {
          MDC.remove("studyId");
          MDC.remove("userId");
        }
      } else {
        if (metric != null) {
          metric.checkpoint("authFail");
        }
        log.warn("Session token could not be authenticated", result.cause());
        rc.response().setStatusCode(401).end("Session expired");
      }
    });
  }
}

