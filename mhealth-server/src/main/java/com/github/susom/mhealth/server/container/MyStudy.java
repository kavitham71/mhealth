package com.github.susom.mhealth.server.container;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.vertx.base.StrictResourceHandler;
import com.github.susom.vertx.base.WebAppJwtAuthHandler;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.Vertx;
import com.github.susom.database.Metric;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

/**
 * This represents a research study web application (browser-facing HTML
 * and AJAX APIs. It delegates user authentication to the centralized
 * portal.
 */
public class MyStudy {
  private static final Logger log = LoggerFactory.getLogger(MyStudy.class);
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final JWTAuth jwt;
  private final Config config;
  private HttpClient httpClient;
  private String portalUrl;
  private String clientId;
  private String clientSecret;
  private String redirectUri;
  private String scope;

  public MyStudy(Builder dbb, SecureRandom secureRandom, JWTAuth jwt, Config config) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.jwt = jwt;
    this.config = config;
    portalUrl = config.getString("portal.url", "http://localhost:8003/participant");
    clientId = config.getString("mystudy.client.id", "mystudyClientId");
    clientSecret = config.getString("mystudy.client.secret", "mystudySecret");
    redirectUri = config.getString("mystudy.redirect.uri", "http://localhost:8004/mystudy/callback");
    scope = config.getString("mystudy.scope", "openid send");
  }

  public Router router(Vertx vertx) {
    if (httpClient == null) {
      httpClient = vertx.createHttpClient(
          new HttpClientOptions().setSsl(portalUrl.startsWith("https")).setConnectTimeout(10000)
      );
    }

    Router router = Router.router(vertx);

    // User session will be picked up from cookie if present,
    // but is optional at this point (upgraded to required below)
    router.route().handler(CookieHandler.create());
    router.route().handler(WebAppJwtAuthHandler.optional(jwt));
    router.route().handler(new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests")));

    // Sample of a public resource that is dynamically loaded
    router.get("/public").handler(rc ->
        rc.response().end("The server says hello!")
    );
    router.get("/broken").handler(rc -> {
      throw new RuntimeException("Eek!");
    });

    // TODO authorization to client for show/hide; enforce for calls

    // Information for the client about whether we are logged in, how to login, etc.
    router.get("/login-status").handler(this::loginStatus);
    router.get("/logout").handler(this::logout);
    router.get("/callback").handler(this::loginCallback);

    // An API that is protected behind user authentication
    router.get("/secret").handler(WebAppJwtAuthHandler.mandatory(jwt));
    router.get("/secret").handler(rc ->
        rc.response().end("The server says some secret stuff!")
    );

    // Study home page and associated static resources
    router.get("/*").handler(new StrictResourceHandler(vertx)
        .addDir("static/mystudy")
        .addDir("static/assets", "**/*", "assets")
        .rootIndex("mystudy.html")
    );

    return router;
  }

  private void loginStatus(RoutingContext rc) {
    User user = rc.user();
    if (user != null) {
      JsonObject principal = user.principal();
      rc.response().end(new JsonObject()
          .put("authenticated", true)
          // TODO issuer; authenticated and acting principal; authority sets
          .put("accountId", principal.getString("sub"))
          .put("userDisplayName", principal.getString("name")).encode());
    } else {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
//        params.addParam("prompt", "TODO");
//        params.addParam("login_hint", "TODO");
//        params.addParam("hd", "TODO");
      params.addParam("redirect_uri", redirectUri);
      String state = new SessionKeyGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setSecure(redirectUri.startsWith("https")).encode());

      rc.response().end(new JsonObject()
          .put("authenticated", false)
          .put("loginUrl", portalUrl + "/login" + params).encode());
    }
  }

  private void loginCallback(RoutingContext rc) {
    String toSiteParam = rc.request().getParam("to");
    String toSite; // TODO validation
    if (toSiteParam == null) {
      toSite = rc.request().absoluteURI();
    } else {
      toSite = toSiteParam;
    }

    // XSRF prevention: Verify the state value provided to login call
    Cookie state = rc.getCookie("state");
    if (state != null) {
      String stateParam = rc.request().getParam("state");
      if (stateParam == null || stateParam.length() == 0) {
        log.debug("Missing state parameter in login callback");
        rc.response().setStatusCode(403).end("Missing state parameter");
        return;
      } else if (!state.getValue().equals(stateParam)) {
        log.debug("State from parameter does not match cookie (XSRF?)");
        rc.response().setStatusCode(403).end("The state parameter does not match the cookie");
        return;
      }
    } else {
      log.error("Something went wrong with login. Could not verify state against"
          + " cookie because the cookie was missing.");
      rc.response().setStatusCode(403).end("The state cookie is missing");
      return;
    }

    QueryStringEncoder enc = new QueryStringEncoder("");

    enc.addParam("grant_type", "authorization_code");
    enc.addParam("code", SessionKeyGenerator.validated(rc.request().getParam("code")));
    enc.addParam("client_id", clientId);
    enc.addParam("client_secret", clientSecret);
    enc.addParam("redirect_uri", redirectUri);
    enc.addParam("scope", scope);

    Metric metric = new Metric(log.isDebugEnabled());
    httpClient.postAbs(portalUrl + "/token", response -> {
      metric.checkpoint("response");
      response.bodyHandler(body -> {
        try {
          metric.checkpoint("body", body.length());
          if (response.statusCode() == 200) {
            JsonObject json = new JsonObject(body.toString());
            String sessionToken = jwt.generateToken(new JsonObject()
                    .put("sub", json.getString("accountId"))
                    .put("name", json.getString("userDisplayName")),
                new JWTOptions().setExpiresInSeconds(60 * 60 * 24));

            Cookie jwtCookie = Cookie.cookie("access_token", sessionToken).setHttpOnly(true)
                .setSecure(redirectUri.startsWith("https"));
            Cookie xsrfCookie = Cookie.cookie("XSRF-TOKEN", new SessionKeyGenerator(secureRandom).create())
                .setSecure(redirectUri.startsWith("https"));

            rc.response().headers()
                .add(SET_COOKIE, jwtCookie.encode())
                .add(SET_COOKIE, xsrfCookie.encode());
            rc.response().setStatusCode(302).putHeader("location", toSite).end();
          } else {
            log.error("Unexpected response connecting to " + portalUrl + "/token: " + response.statusCode() + " "
                + response.statusMessage() + " body: " + body);
            rc.response().setStatusCode(500).end("Bad response from token endpoint");
          }
        } catch (Exception e) {
          log.error("Unexpected error connecting to " + portalUrl + "/token: " + response.statusCode() + " "
              + response.statusMessage() + " body: " + body);
          rc.response().setStatusCode(500).end("Bad response from token endpoint");
        } finally {
          log.debug("Request token: {}", metric.getMessage());
        }
      });
    }).exceptionHandler(e -> {
      try {
        log.error("Unexpected error connecting to " + portalUrl + "/token", e);
        rc.response().setStatusCode(500).end("Bad response from token endpoint");
      } finally {
        log.debug("Request token: {}", metric.getMessage());
      }
    }).putHeader("content-type", "application/x-www-form-urlencoded")
        .putHeader("X-REQUEST-ID", MDC.get("requestId"))
        .end(enc.toString().substring(1));
  }

  private void logout(RoutingContext rc) {
//      QueryStringEncoder toEnc = new QueryStringEncoder("");
//      toEnc.addParam("client_id", clientId);
//      toEnc.addParam("scope", scope);
//      toEnc.addParam("to", rc.request().getParam("from"));
    QueryStringEncoder fromEnc = new QueryStringEncoder("");
//      fromEnc.addParam("from", portalUrl + "/login" + toEnc);
    fromEnc.addParam("from", rc.request().getParam("from"));

    rc.response().headers()
        .add(SET_COOKIE, Cookie.cookie("access_token", "").setMaxAge(0).encode())
        .add(SET_COOKIE, Cookie.cookie("XSRF-TOKEN", "").setMaxAge(0).encode())
        .add("location", portalUrl + "/logout" + fromEnc);
    rc.response().setStatusCode(302).end();
  }
}
