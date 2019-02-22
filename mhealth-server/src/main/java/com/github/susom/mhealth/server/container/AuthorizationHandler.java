package com.github.susom.mhealth.server.container;

import com.github.susom.database.Metric;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Ensure the user is consented and has not left the study.
 */
public class AuthorizationHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(JwtAuthHandler.class);

  public void handle(RoutingContext rc) {

    Metric metric = rc.get("metric");
    if (metric != null) {
      metric.checkpoint("authurization");
    }
    Boolean consented = rc.get("consented");
    if (!consented) {
      log.warn("User not authorized");
      rc.response().setStatusCode(403).end("Not Consented");
    } else {
      rc.next();
    }
  }
}

