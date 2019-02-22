package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.Metric;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A client that talks to the 23andMe API to retrieve various
 * information about one of their users.
 *
 * @author garricko
 */
public class SageReal implements SageApi {
  private static final Logger log = LoggerFactory.getLogger(SageReal.class);
  private final Config config;
  private final HttpClient client;

  public SageReal(Vertx vertx, Config config) {
    this.config = config;
    // Their QA sandbox has bogus certs (self-signed and the host name doesn't match)
    boolean insecureSsl = config.getBooleanOrFalse("sage.insecure.ssl");
    client = vertx.createHttpClient(new HttpClientOptions().setSsl(true)
        .setTrustAll(insecureSsl).setVerifyHost(!insecureSsl));
  }

  @Override
  //This method succeedes only if the sageSession is not null, sage status is enabled and the email in the input 
  // argument is same as the sage email for the participant.

  public void getParticipants(String sageSession, String email, Handler<AsyncResult<StudyParticipant>> handler) {
    Metric metric = new Metric(log.isDebugEnabled());
    String url = config.getString("sage.url");
    if (sageSession == null) {
      JsonObject ex = new JsonObject();
      ex.put("statusCode", 500);
      ex.put("message", "Sage session is null");
      handler.handle(Future.failedFuture(ex.encode()));
    } else {
    client.get(443, config.getString("sage.host"), url, response -> {
      try {
        metric.checkpoint("response", response.statusCode());
        response.bodyHandler(body -> {
          metric.checkpoint("body", body.length());
          if (response.statusCode() == 200) {
            JsonObject json = body.toJsonObject();
            StudyParticipant participant = new StudyParticipant();
            participant.email = json.getString("email");
            participant.status = json.getString("status");
            TimeZone tz = TimeZone.getTimeZone("UTC");
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSZZ");
            participant.createdOn = Date.from(json.getInstant("createdOn"));
            participant.id = json.getString("id");
            if (participant.status.equals("enabled") && participant.email.equals(email)) {
              handler.handle(Future.succeededFuture(participant));
            } else {
              JsonObject ex = new JsonObject();
              ex.put("statusCode", 500);
              ex.put("message", "Participant status in sage is not enabled.Or the mhealth email not same as sage email"
                  + " sageEmail: " + participant.email + " sageStatus:" + participant.status);
              handler.handle(Future.failedFuture(ex.encode()));
            }
            metric.checkpoint("success");
          } else {
            String bodyString = body.toString();
            log.error("The getParticipants api returned status " + response.statusCode()
                + " " + response.statusMessage() + " with body " + bodyString);
            JsonObject result = new JsonObject();
            result.put("statusCode", response.statusCode());
            if (response.statusCode() != 404 && bodyString.length() < 200) {
              result.put("message", bodyString);
            } else {
              result.put("message", "Not Found");
            }
            handler.handle(Future.failedFuture(result.encode()));
            metric.checkpoint("fail");
          }
        });
      } catch (Exception e) {
        log.error("Error while invoking the participants end point on sage", e);
        handler.handle(Future.failedFuture(e));
        metric.checkpoint("error");
      } finally {
        if (log.isDebugEnabled()) {
          log.debug("Sage data: " + metric.getMessage());
        }
      }
    }).exceptionHandler(exception -> {
      log.error("The getParticipants api returned error", exception);
      JsonObject ex = new JsonObject();
      ex.put("statusCode", 500);
      ex.put("message", "Exception invoking the getParticipants api on Sage." + exception.getMessage());
      handler.handle(Future.failedFuture(ex.encode()));
    }).putHeader("Bridge-Session", sageSession).end();
  }
  }
}
