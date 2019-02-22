package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.MyHeartCountsApi;
import com.github.susom.mhealth.server.apis.PortalServerApi;
import com.github.susom.mhealth.server.apis.SageApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import com.github.susom.mhealth.server.container.ParticipantPortal;
import com.github.susom.mhealth.server.services.Mailer;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import java.security.SecureRandom;
import java.util.Date;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class SignUpWithSageDbTest {
  private Vertx vertx;
  @Mock
  private Mailer mailer;
  @Mock
  private JWTAuth jwt;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  @Mock
  private SageApi sageApi;

  @Before
  public void setUp(TestContext context) throws Exception {
    MockitoAnnotations.initMocks(this);

    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    vertx = Vertx.vertx();

    String propertiesFile = System.getProperty("local.properties", "../local.properties");
    Config config = Config.from().value("portal.url", "http://localhost:8003/participant")
        .systemProperties().propertyFile(propertiesFile).get();
    realDbb = DatabaseProviderVertx.pooledBuilder(vertx, config).withSqlParameterLogging()
        .withSqlInExceptionMessages();
    realDbp = realDbb.create();
    Builder dbb = realDbp.fakeBuilder();
    SecureRandom random = new SecureRandom();

    Router root = Router.router(vertx);
    root.mountSubRouter("/server", new PortalServerApi(dbb, random, mailer, config, sageApi).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8002, context.asyncAssertSuccess());

    root = Router.router(vertx);
    root.mountSubRouter("/participant", new ParticipantPortal(dbb, random, mailer, config).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8003, context.asyncAssertSuccess());

    root = Router.router(vertx);
    TwentyThreeAndMeReal twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);
    TwentyThreeAndMeApi twentyThree = new TwentyThreeAndMeApi(dbb, random, config, twentyThreeAndMe);
    root.mountSubRouter("/mhc", new MyHeartCountsApi(dbb, random, jwt, config, vertx, twentyThree).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8001, context.asyncAssertSuccess());
  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  //This test the sage session has an enabled email, so no email verification required
  public void testSignUpWithEmailEnabledAndSignIn(TestContext context) {
    SageApi.StudyParticipant studyParticipant = new SageApi.StudyParticipant();
    studyParticipant.email = "me@example.com";
    studyParticipant.createdOn = new Date(11 / 15 / 2016);
    studyParticipant.externalId = "1";
    studyParticipant.firstName = "me";
    studyParticipant.lastName = "mo";
    studyParticipant.status = "enabled";
    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    doNothing().when(sageApi).getParticipants(eq("sageSession"), eq("me@example.com"),
        argThat(new Callback<Handler<AsyncResult<SageApi.StudyParticipant>>>(h -> {
          h.handle(Future.succeededFuture(studyParticipant));
        })));
    Async async = context.async();
    String password = StringUtils.leftPad("123", 32, "a");

    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/auth/signUp", signUpResponse -> {
      context.assertEquals(201, signUpResponse.statusCode());

      signUpResponse.bodyHandler(signUpJson -> {
        System.out.println("SignUp JSON: " + signUpJson);
        String username = new JsonObject(signUpJson.toString()).getString("username");
        User user = mock(User.class);
        when(user.principal()).thenReturn(new JsonObject().put("sub", username));
        doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());

        client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
          context.assertEquals(412, signInResponse.statusCode());

          signInResponse.bodyHandler(sessionInfoBody -> {
            System.out.println("SessionInfo: " + sessionInfoBody);
            JsonObject sessionInfoJson = new JsonObject(sessionInfoBody.toString());
            context.assertTrue(sessionInfoJson.getBoolean("authenticated"));
            context.assertFalse(sessionInfoJson.getBoolean("consented"));
            context.assertEquals("mytoken123", sessionInfoJson.getString("sessionToken"));
            client.post(8001, "localhost", "/mhc/api/v1/consent", consentResponse -> {
              context.assertEquals(201, consentResponse.statusCode());

              consentResponse.bodyHandler(response -> {
                context.assertTrue(response.toString().contains("Consent to research has been recorded"));
                client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInSuccessResponse -> {
                  context.assertEquals(200, signInSuccessResponse.statusCode());
                  async.complete();
                }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                    .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\": \""
                        + password + "\"}");
              });

            }).exceptionHandler(context::fail).putHeader("Bridge-Session", "mytoken123")
                .putHeader("content-type", "application/json").end("{\"name\":\"" + "me@example.com"
                    + "\",\"scope\":\"ALL_QUALIFIED_RESEARCHERS\",\"birthdate\":\"2011-12-13\"}");
          });

        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password
                + "\"}");
      });
      //}).exceptionHandler(context::fail).end();
      // });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "sageSession")
        .end("{\"email\":\"me@example.com\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password + "\"}");

    verifyNoMoreInteractions(mailer);

  }

  @Test
  public void testSignUpWithSageError(TestContext context) {
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    doNothing().when(sageApi).getParticipants(eq("sageSession"), eq("me@example.com"),
        argThat(new Callback<Handler<AsyncResult<SageApi.StudyParticipant>>>(
            h -> h.handle(Future.failedFuture("{\"statusCode\":"
                + 401 + ",\"message\":"
                + "\"Unauthorized\"" + "}")))));
    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);
    Async async = context.async();
    String password = StringUtils.leftPad("123", 32, "a");

    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/auth/signUp", signUpResponse -> {
      context.assertEquals(201, signUpResponse.statusCode());

      signUpResponse.bodyHandler(signUpJson -> {
        System.out.println("SignUp JSON: " + signUpJson);
        String username = new JsonObject(signUpJson.toString()).getString("username");
        User user = mock(User.class);
        when(user.principal()).thenReturn(new JsonObject().put("sub", username));
        doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
        //There was a sage error so verification email was send again.Trying to signIn without verification gives 403   
        client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
          context.assertEquals(403, signInResponse.statusCode());
          async.complete();
        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password
                + "\"}");
      });
      //}).exceptionHandler(context::fail).end();
      // });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "sageSession")
        .end("{\"email\":\"me@example.com\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password + "\"}");

    verifyNoMoreInteractions(mailer);

  }

  @Test
  public void testSignUpWithEmailNotEnabledWithoutEmailVerification(TestContext context) {

    SageApi.StudyParticipant studyParticipant = new SageApi.StudyParticipant();
    studyParticipant.email = "me@example.com";
    studyParticipant.createdOn = new Date(11 / 15 / 2016);
    studyParticipant.externalId = "1";
    studyParticipant.firstName = "me";
    studyParticipant.lastName = "mo";
    studyParticipant.status = "disabled";
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    // doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);
    doNothing().when(sageApi).getParticipants(eq("sageSession"), eq("me@example.com"),
        argThat(new Callback<Handler<AsyncResult<SageApi.StudyParticipant>>>(
            h -> h.handle(Future.failedFuture("{\"statusCode\":"
                + 500 + ",\"message\":"
                + "\"Status disabled\"" + "}")))));
    Async async = context.async();
    String password = StringUtils.leftPad("678", 32, "a");

    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/auth/signUp", signUpResponse -> {
      context.assertEquals(201, signUpResponse.statusCode());

      signUpResponse.bodyHandler(signUpJson -> {
        System.out.println("SignUp JSON: " + signUpJson);
        String username = new JsonObject(signUpJson.toString()).getString("username");
        doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
        when(user.principal()).thenReturn(new JsonObject().put("sub", username));
        // Extract the email link
        // from our mailer stub so we can "click" it
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(mailer).sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null),
            eq("me@example.com"), eq(null), eq(null), eq("Verify your Account"), argument.capture());
        String email = argument.getValue();
        System.out.println("Email: " + email);
        String link = email.substring(email.indexOf("http"), email.indexOf("\"", email.indexOf("http")));
        System.out.println("Link: " + link);

        client.getAbs(link, clickEmailResponse -> {
          context.assertEquals(200, clickEmailResponse.statusCode());

          clickEmailResponse.bodyHandler(verifiedHtml -> {
            System.out.println("Verified HTML: " + verifiedHtml);
            context.assertTrue(verifiedHtml.toString().contains("has now been verified"));

            client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
              context.assertEquals(412, signInResponse.statusCode());

              signInResponse.bodyHandler(sessionInfoBody -> {
                System.out.println("SessionInfo: " + sessionInfoBody);
                JsonObject sessionInfoJson = new JsonObject(sessionInfoBody.toString());
                context.assertTrue(sessionInfoJson.getBoolean("authenticated"));
                context.assertFalse(sessionInfoJson.getBoolean("consented"));
                context.assertEquals("mytoken123", sessionInfoJson.getString("sessionToken"));
                client.post(8001, "localhost", "/mhc/api/v1/consent", consentResponse -> {
                  context.assertEquals(201, consentResponse.statusCode());
                  consentResponse.bodyHandler(response -> {
                    context.assertTrue(response.toString().contains("Consent to research has been recorded"));
                    client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInSuccessResponse -> {
                      context.assertEquals(200, signInSuccessResponse.statusCode());
                      async.complete();
                    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                        .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular"
                            + "\",\"password\": \"" + password + "\"}");
                  });

                }).exceptionHandler(context::fail).putHeader("Bridge-Session", "mytoken123")
                    .putHeader("content-type", "application/json").end("{\"name\":\"" + "me@example.com"
                        + "\",\"scope\":\"ALL_QUALIFIED_RESEARCHERS\",\"birthdate\":\"2011-12-13\"}");
              });

            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\""
                    + password + "\"}");
          });
        }).exceptionHandler(context::fail).end();
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "sageSession")
        .end("{\"email\":\"me@example.com\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password + "\"}");

    verifyNoMoreInteractions(mailer);

  }

  @NotNull
  @SuppressWarnings("unchecked")
  private Answer callback(final User user, int argIndex) {
    return invocation -> {
      ((Handler<AsyncResult<User>>) invocation.getArguments()[argIndex]).handle(new AsyncResult<User>() {
        @Override
        public User result() {
          return user;
        }

        @Override
        public Throwable cause() {
          return null;
        }

        @Override
        public boolean succeeded() {
          return true;
        }

        @Override
        public boolean failed() {
          return false;
        }
      });
      return null;
    };
  }
}
