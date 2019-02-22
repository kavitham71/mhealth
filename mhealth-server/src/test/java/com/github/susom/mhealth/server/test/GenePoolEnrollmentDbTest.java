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
import com.github.susom.mhealth.server.container.ParticipantPortal;
import com.github.susom.mhealth.server.services.Mailer;
import io.vertx.core.AsyncResult;
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
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;
import org.mockito.ArgumentCaptor;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class GenePoolEnrollmentDbTest {
  private Vertx vertx;
  @Mock
  private Mailer mailer;
  @Mock
  private JWTAuth jwt;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  private SageApi sageApi;
  private int requiredField = 0;
  private static final int TEST_REQUIRED_attending_physician_names = 1;
  private static final int TEST_REQUIRED_participant_mrn = 2;
  private static final int TEST_REQUIRED_participant_name = 3;
  private static final int TEST_REQUIRED_name = 4;
  private static final int TEST_REQUIRED_email_address = 5;
  private static final int TEST_NULLABLE_FIELDS = 5;
  private static final int TEST_CROSS_VALIDATION = 6;

  @Before
  public void setUp(TestContext context) throws Exception {
    MockitoAnnotations.initMocks(this);

    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    vertx = Vertx.vertx();

    String propertiesFile = System.getProperty("local.properties", "./local.properties");
    Config config = Config.from().value("portal.url", "http://localhost:8003/participant")
        .systemProperties().propertyFile(propertiesFile).get();
    realDbb = DatabaseProviderVertx.pooledBuilder(vertx, config).withSqlParameterLogging()
        .withSqlInExceptionMessages();
    realDbp = realDbb.create();
    Builder dbb = realDbp.fakeBuilder();
    SecureRandom random = new SecureRandom();

    Router root = Router.router(vertx);
    sageApi = new SageReal(vertx, config);
    root.mountSubRouter("/server", new PortalServerApi(dbb, random, mailer, config, sageApi).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8002, context.asyncAssertSuccess());
    //vertx.createHttpServer().requestHandler(root::accept).listen(8002, context.asyncAssertSuccess());

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
  public void testSignUp_Signin_Consented_Signin_Signout(TestContext context) {

    when(mailer.sendHtml(eq("GenePool<genepool-support@stanford.edu>"), eq(null), eq("me@example.com"),
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
/*

        verify(mailer).sendHtml(eq("GenePool<genepool-support@stanford.edu>"), eq(null),
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
*/
        client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
          context.assertEquals(412, signInResponse.statusCode());

          signInResponse.bodyHandler(sessionInfoBody -> {
            System.out.println("SessionInfo: " + sessionInfoBody);
            JsonObject sessionInfoJson = new JsonObject(sessionInfoBody.toString());
            context.assertTrue(sessionInfoJson.getBoolean("authenticated"));
            context.assertFalse(sessionInfoJson.getBoolean("consented"));
            context.assertEquals("mytoken123", sessionInfoJson.getString("sessionToken"));
            JsonObject consent = new JsonObject();

            consent.put("name", "James Test");
            //consent.put("zip_code", 12345);
            consent.put("birthdate", "2011-08-16");
/*                 consent.put("race", "american");
                consent.put("ethnicity", "asian");




                consent.put("share_with_nih", true);
                consent.put("do_not_inform_genetic_findings", false);
                consent.put("both_genetic_findings", false);
                consent.put("related_to_family_history", true);
                consent.put("treatable_genetic_findings", false);
                consent.put("family_history_of_disease", "high blood pressure");
                consent.put("stanford_research_registry", true);

                consent.put("is_adult_participant",true);
*/

            //Newly add fields testing
            if (requiredField == 0) {
              //test newly add fields
              consent.put("is_adult_participant", true);
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              consent.put("email_address", "jinxuejim@gmail.com");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");

            } else if (requiredField == TEST_REQUIRED_attending_physician_names) {  // 1
              //test newly add fields
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");
              //consent.put("attending_physicia_name", "attending_physicia_name");

            } else if (requiredField == TEST_REQUIRED_participant_mrn) {
              //test newly add fields
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");
              consent.put("attending_physicia_name", "attending_physicia_name");

            } else if (requiredField == TEST_REQUIRED_participant_name) {
              //test newly add fields
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");
              consent.put("attending_physicia_name", "attending_physicia_name");

            } else if (requiredField == TEST_REQUIRED_name) {
              //test newly add fields
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");
              consent.put("attending_physicia_name", "attending_physicia_name");

            } else if (requiredField == TEST_REQUIRED_email_address) {
              //test newly add fields
              consent.put("opt_out", true);
              consent.put("gender", "");
              consent.put("receive_biochemical_tests", true);
              consent.put("submit_urine_sample", true);
              consent.put("assent_child_name", "assenntChildName");
              consent.put("assent_adult_name", "assent name");
              consent.put("child_cannot_assent", false);
              consent.put("participant_name", "participantname");
              //consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");
              consent.put("attending_physicia_name", "attending_physicia_name");

            } else if (requiredField == TEST_NULLABLE_FIELDS) {
              //test newly add fields

              consent.put("participant_name", "participantname");
              consent.put("email_address", "jamesxue@stanford.edu");
              consent.put("participant_mrn", "participant_mrn");
              consent.put("attending_physician_name", "attending_physician_name");

            } else if (requiredField == TEST_CROSS_VALIDATION) {
              consent.put("share_with_nih", true);

              consent.put("related_to_family_history", false);
              consent.put("family_history_of_disease", "high blood pressure");
            }
            System.out.println("before call consent=====" + consent);
            client.post(8001, "localhost", "/mhc/api/v1/consent", consentResponse -> {
              context.assertEquals(201, consentResponse.statusCode());
              System.out.println("inside call consent=====" + consent);
              consentResponse.bodyHandler(response -> {

                System.out.println("inside call consent1=====" + consent);
                context.assertTrue(response.toString().contains("Consent to research has been recorded"));
                client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInSuccessResponse -> {
                  context.assertEquals(200, signInSuccessResponse.statusCode());
                  System.out.println("sign in successful=====");
                  //Same user signUp again from different device The signIn should go smoothly without needing to consent again
                  client.post(8001, "localhost", "/mhc/api/v1/auth/signUp", signUpResponse2 -> {
                    context.assertEquals(201, signUpResponse2.statusCode());
                    signUpResponse2.bodyHandler(signUp2Json -> {
                      System.out.println("SignUp JSON: " + signUpJson);
                      String username2 = new JsonObject(signUpJson.toString()).getString("username");
                      User user2 = mock(User.class);
                      when(user2.principal()).thenReturn(new JsonObject().put("sub", "456"));
                      doAnswer(callback(user2, 1)).when(jwt).authenticate(any(), any());
                      client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse2 -> {
                        context.assertEquals(200, signInResponse2.statusCode());
                        //context.assertTrue(response.toString().contains("Consent to research has been recorded"));

                        async.complete();

                      }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                          .end("{\"study\":\"genepool" + "\",\"username\":\"" + username2 + "\",\"password\": \""
                              + password + "\"}");
                    });
                  }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                      .end("{\"study\":\"genepool" + "\",\"email\":\"me@example.com" + "\",\"password\":\""
                          + password + "\"}");
                }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                    .end("{\"study\":\"genepool" + "\",\"username\":\"" + username + "\",\"password\": \""
                        + password + "\"}");
              }).exceptionHandler(context::fail).statusMessage();


            }).exceptionHandler(context::fail).putHeader("Bridge-Session", "mytoken123")
                .putHeader("content-type", "application/json").end(consent.encodePrettily());

          }).exceptionHandler(context::fail).statusMessage();

        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end("{\"study\":\"genepool" + "\",\"username\":\"" + username + "\",\"password\":\"" + password
                + "\"}");

/*

          });
        }).exceptionHandler(context::fail).end();
*/
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .end("{\"study\":\"genepool" + "\",\"email\":\"me@example.com" + "\",\"password\":\"" + password + "\"}");


    verifyNoMoreInteractions(mailer);

  }


  // verify the result by select from db

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
  //@Test

  public void testRequired_attending_physician_names(TestContext context) {
    requiredField = TEST_REQUIRED_attending_physician_names;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }

  @Test
  public void testRequired_participant_mrn(TestContext context) {

    requiredField = TEST_REQUIRED_participant_mrn;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }

  @Test
  public void testRequired_participant_name(TestContext context) {
    requiredField = TEST_REQUIRED_participant_name;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }

  public void testRequired_name(TestContext context) {
    requiredField = TEST_REQUIRED_name;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }

  @Test
  public void testRequired_email_address(TestContext context) {
    requiredField = TEST_REQUIRED_email_address;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }

  @Test
  public void testNullableFields(TestContext context) {
    requiredField = TEST_NULLABLE_FIELDS;
    testSignUp_Signin_Consented_Signin_Signout(context);
  }


}
