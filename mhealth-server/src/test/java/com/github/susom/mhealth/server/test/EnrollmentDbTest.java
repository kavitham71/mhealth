package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.MyHeartCountsApi;
import com.github.susom.mhealth.server.apis.PortalServerApi;
import com.github.susom.mhealth.server.apis.SageApi;
import com.github.susom.mhealth.server.apis.SageReal;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import com.github.susom.mhealth.server.apis.UploadRequest;
import com.github.susom.mhealth.server.container.ParticipantPortal;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.mhealth.server.services.MyPartDao;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import java.security.SecureRandom;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class EnrollmentDbTest {
  private Vertx vertx;
  @Mock
  private Mailer mailer;
  @Mock
  private JWTAuth jwt;
  private Builder realDbb;
  private Builder dbb;
  private DatabaseProviderVertx realDbp;
  private SageApi sageApi;
  private SecureRandom random;

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
    dbb = realDbp.fakeBuilder();
    random = new SecureRandom();

    Router root = Router.router(vertx);
    sageApi = new SageReal(vertx, config);
    root.mountSubRouter("/server", new PortalServerApi(dbb, random, mailer, config, sageApi).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8002, context.asyncAssertSuccess());

    root = Router.router(vertx);
    root.mountSubRouter("/participant", new ParticipantPortal(dbb, random, mailer, config).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8003, context.asyncAssertSuccess());

    root = Router.router(vertx);
    TwentyThreeAndMeReal twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);
    TwentyThreeAndMeApi twentyThree = new TwentyThreeAndMeApi(dbb, random, config, twentyThreeAndMe);
    MyHeartCountsApi mhcApi = new MyHeartCountsApi(dbb, random, jwt, config, vertx, twentyThree);
    vertx.getOrCreateContext().runOnContext(v ->
      mhcApi.loadInvalidTokenCache(r -> {
        if (r.succeeded()) {
           System.out.println("loaded cache successfully");
        } else {
           System.out.println("unable to load cache");
        }
      })
    );
    root.mountSubRouter("/mhc", mhcApi.router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8001, context.asyncAssertSuccess());
  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void testSignUpAndSignIn(TestContext context) {

    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");

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
                    + "\",\"scope\":\"ALL_QUALIFIED_RESEARCHERS\",\"birthdate\":\"2011-08-16\"}");
              });

            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\""
                    + password + "\"}");
          });
        }).exceptionHandler(context::fail).end();
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .end("{\"study\":\"cardiovascular\",\"email\":\"me@example.com" + "\",\"password\":\"" + password + "\"}");

    verifyNoMoreInteractions(mailer);

  }

  @Test
  public void testSignUpAndSignInWithDrawSignIn(TestContext context) {
    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");

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
        // Extract the email link
        // from our mailer stub so we can "click" it
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(mailer).sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me@example.com"), eq(null), eq(null), eq("Verify your Account"), argument.capture());
        String email = argument.getAllValues().get(0);
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
                      when(user.principal()).thenReturn(new JsonObject().put("sub", username).put("consented", true));
                      client.getAbs("http://localhost:8001/mhc/api/v1/auth/withdraw", withdrawResponse -> {
                       context.assertEquals(200, withdrawResponse.statusCode());
                        client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInAfterWithdrawResponse -> {
                          context.assertEquals(412, signInAfterWithdrawResponse.statusCode());
                          UploadRequest request = new UploadRequest();
                          request.setName("decrypted-3.zip");
                          request.setContentLength(1024);
                          request.setContentMd5("6RQ57lzGqQV+SXHQFxZCFQ==");
                         client.post(8001, "localhost", "/mhc/api/v1/upload", uploadResponse ->  {
                            context.assertEquals(401, uploadResponse.statusCode());
                            async.complete();
                           // signUpAgainResponse.bodyHandler(signUpAgainJson -> {
                            //  System.out.println("SignUp JSON: " + signUpAgainJson);
                            //  String username1 = new JsonObject(signUpAgainJson.toString()).getString("username");
                            //  when(user.principal()).thenReturn(new JsonObject().put("sub", username1));
                              // Extract the email link
                              // from our mailer stub so we can "click"
                             // ArgumentCaptor<String> argument1 = ArgumentCaptor.forClass(String.class);
                            //  verify(mailer).sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null),
                             //    eq("me@example.com"), eq(null), eq(null), eq("Verify your Account"), argument1.capture());
                             // List<String> emails = argument1.getAllValues();
                            //  String email1 = argument1.getAllValues().get(0);
                             // System.out.println("Email: " + email1);
                            //  String link1 = email1.substring(email1.indexOf("http"), email1.indexOf("\"", email1.indexOf("http")));
                             // System.out.println("Link: " + link1);

                              //client.getAbs(link1, clickEmailResponse1 -> {
                               // context.assertEquals(200, clickEmailResponse1.statusCode());

                                //clickEmailResponse1.bodyHandler(verifiedHtml1 -> {
                                 // System.out.println("Verified HTML: " + verifiedHtml1);
                                 // context.assertTrue(verifiedHtml1.toString().contains("has now been verified"));

                                  //client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse2 -> {
                                  //  context.assertEquals(403, signInResponse2.statusCode());
                                 //   async.complete();
                                  //}).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                                    //  .end("{\"username\":\"" + username1 + "\",\"study\":\"" + "cardiovascular"
                                       //   + "\",\"password\": \"" + password + "\"}");
                                //});
                              //});
                           // });
                          }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                             .putHeader("Bridge-Session", "mytoken123")
                             .end(Json.encode(request));
                        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                            .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular"
                                + "\",\"password\": \"" + password + "\"}");
                     }).exceptionHandler(context::fail).putHeader("Bridge-Session", "mytoken123").end();
                    //});
                    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                        .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular"
                            + "\",\"password\": \"" + password + "\"}");
                  });

                }).exceptionHandler(context::fail).putHeader("Bridge-Session", "mytoken123")
                    .putHeader("content-type", "application/json").end("{\"name\":\"" + "me@example.com"
                    + "\",\"scope\":\"ALL_QUALIFIED_RESEARCHERS\",\"birthdate\":\"2011-08-16\"}");
              });

            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\""
                    + password + "\"}");
          });
        }).exceptionHandler(context::fail).end();
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .end("{\"study\":\"cardiovascular\",\"email\":\"me@example.com" + "\",\"password\":\"" + password + "\"}");

    verifyNoMoreInteractions(mailer);

  }

  @Test
  public void testSignInWithoutEmailVerification(TestContext context) {

    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    // doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    when(mailer.sendHtml(eq("MyHeart Counts <myheartcounts-support@stanford.edu>"), eq(null), eq("me2@gmail.com"),
        eq(null), eq(null), eq("Verify your Account"), anyString())).thenReturn(true);


    Async async = context.async();
    String password = StringUtils.leftPad("678", 32, "a");

    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/auth/signUp", signUpResponse -> {
      context.assertEquals(201, signUpResponse.statusCode());

      signUpResponse.bodyHandler(signUpJson -> {
        System.out.println("SignUp JSON: " + signUpJson);
        String username = new JsonObject(signUpJson.toString()).getString("username");

        client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
          context.assertEquals(403, signInResponse.statusCode());

          signInResponse.bodyHandler(sessionInfoBody -> {
            System.out.println("SessionInfo: " + sessionInfoBody);
            context.assertTrue(sessionInfoBody.toString().contains("Device not verified or no longer allowed"));

            async.complete();
          });

        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end("{\"username\":\"" + username + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\"" + password
                + "\"}");

      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .end("{\"study\":\"cardiovascular\",\"email\":\"me2@gmail.com" + "\",\"password\":\"" + password + "\"}");

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
