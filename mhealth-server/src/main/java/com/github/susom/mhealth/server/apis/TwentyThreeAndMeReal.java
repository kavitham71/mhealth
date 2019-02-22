package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.Metric;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A client that talks to the 23andMe API to retrieve various
 * information about one of their users.
 *
 * @author garricko
 */
public class TwentyThreeAndMeReal implements TwentyThreeAndMe {
  private static final Logger log = LoggerFactory.getLogger(TwentyThreeAndMeReal.class);
  private final Config config;
  private final HttpClient client;

  public TwentyThreeAndMeReal(Vertx vertx, Config config) {
    this.config = config;
    // Their QA sandbox has bogus certs (self-signed and the host name doesn't match)
    boolean insecureSsl = config.getBooleanOrFalse("23andme.insecure.ssl");
    client = vertx.createHttpClient(new HttpClientOptions().setSsl(true)
        .setTrustAll(insecureSsl).setVerifyHost(!insecureSsl));
  }

  @Override
  public void refreshToken(String refreshToken, Handler<AsyncResult<RefreshResult>> handler) {
    Metric metric = new Metric(log.isDebugEnabled());

    QueryStringEncoder enc = new QueryStringEncoder("");

    enc.addParam("client_id", config.getString("23andme.client.id"));

    enc.addParam("client_secret", config.getString("23andme.client.secret"));

    enc.addParam("grant_type", "refresh_token");

    enc.addParam("refresh_token", refreshToken);

    enc.addParam("redirect_uri", config.getString("23andme.redirect.uri"));

    enc.addParam("scope", "genomes basic");

    String encodedBody = enc.toString().substring(1);

    client.post(443, config.getString("23andme.host"), config.getString("23andme.refreshToken.url"), response -> {
      try {
        metric.checkpoint("response", response.statusCode());
        response.bodyHandler(body -> {
          try {
            metric.checkpoint("body", body.length());
            if (response.statusCode() == 200) {
              JsonObject token = body.toJsonObject();

              RefreshResult result = new RefreshResult();
              result.accessToken = token.getString("access_token");
              result.refreshToken = token.getString("refresh_token");

              handler.handle(Future.succeededFuture(result));
              metric.checkpoint("success");
            } else {
              String bodyString = body.toString();
              log.error("The get refresh token api returned status " + response.statusCode()
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
          } finally {
            if (log.isDebugEnabled()) {
              log.debug("Refresh token: " + metric.getMessage());
            }
          }
        });
      } catch (Exception e) {
        log.error("Exception while invoking refreshToken end point on 23andMe: " + metric.getMessage(), e);
        handler.handle(Future.failedFuture(e));
      }
    }).exceptionHandler(exception -> {
      log.error("The get refresh token api returned error", exception);
      JsonObject ex = new JsonObject();
      ex.put("statusCode", 500);
      ex.put("message", "Exception invoking the 23andme refresh token api");
      handler.handle(Future.failedFuture(ex.encode()));
    }).putHeader("content-type", "application/x-www-form-urlencoded")
        .end(encodedBody);
  }

  @Override
  public void userInfo(String accessToken, Handler<AsyncResult<UserResult>> handler) {
    Metric metric = new Metric(log.isDebugEnabled());

    client.get(443, config.getString("23andme.host"), config.getString("23andme.userInfo.url"), response -> {
      try {
        metric.checkpoint("response", response.statusCode());
        response.bodyHandler(body -> {
          metric.checkpoint("body", body.length());
          if (response.statusCode() == 200) {
            JsonObject user = body.toJsonObject();
            UserResult userInfo = new UserResult();
            userInfo.id = user.getString("id");
            for (Object profile : user.getJsonArray("profiles")) {
              Profile prof = new Profile();
              prof.id = ((JsonObject) profile).getString("id");
              prof.genotyped = ((JsonObject) profile).getBoolean("genotyped");
              if (userInfo.profiles == null) {
                userInfo.profiles = new ArrayList<>();
              }
              userInfo.profiles.add(prof);
            }
            handler.handle(Future.succeededFuture(userInfo));
            metric.checkpoint("success");
          } else {
            String bodyString = body.toString();
            log.debug("The user api returned status " + response.statusCode()
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
        log.error("Exception while invoking user end point on 23andme", e);
        handler.handle(Future.failedFuture(e));
        metric.checkpoint("error");
      } finally {
        if (log.isDebugEnabled()) {
          log.debug("User info: " + metric.getMessage());
        }
      }
    }).exceptionHandler(exception -> {
      log.error("The user api returned error", exception);
      JsonObject ex = new JsonObject();
      ex.put("statusCode", 500);
      ex.put("message", "Exception invoking the 23andme user api");
      handler.handle(Future.failedFuture(ex.encode()));
    }).putHeader("Authorization", "Bearer " + accessToken).end();
  }

  @Override
  public void geneticData(String profileId, String accessToken, Handler<AsyncResult<GenomeData>> handler) {
    Metric metric = new Metric(log.isDebugEnabled());

    String url = config.getString("23andme.geneticData.url") + profileId + "/";
    client.get(443, config.getString("23andme.host"), url, response -> {
      try {
        metric.checkpoint("response", response.statusCode());
        response.bodyHandler(body -> {
          metric.checkpoint("body", body.length());
          if (response.statusCode() == 200) {
            JsonObject json = body.toJsonObject();
            GenomeData genomeData = new GenomeData();
            genomeData.id = json.getString("id");
            genomeData.genome = json.getString("genome");
            handler.handle(Future.succeededFuture(genomeData));
            metric.checkpoint("success");
          } else {
            String bodyString = body.toString();
            log.error("The geneticData api returned status " + response.statusCode()
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
        log.error("Error while invoking the genome end point on 23andme", e);
        handler.handle(Future.failedFuture(e));
        metric.checkpoint("error");
      } finally {
        if (log.isDebugEnabled()) {
          log.debug("Genetic data: " + metric.getMessage());
        }
      }
    }).exceptionHandler(exception -> {
      log.error("The geneticData api returned error", exception);
      JsonObject ex = new JsonObject();
      ex.put("statusCode", 500);
      ex.put("message", "Exception invoking the 23andme genetic data api");
      handler.handle(Future.failedFuture(ex.encode()));
    }).putHeader("Authorization", "Bearer " + accessToken).end();
  }
}
