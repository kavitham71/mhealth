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
import com.github.susom.mhealth.server.services.MhealthDao;
import com.github.susom.mhealth.server.services.MyPartDao;
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
import java.util.Calendar;
import java.util.GregorianCalendar;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class DataSharingDbTest {
  private Vertx vertx;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  @Mock
  private Mailer mailer;
  @Mock
  private JWTAuth jwt;
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

    // set up the database to get past signUp and SignIn
    dbb.transact(dbp -> {
      MyPartDao myPart = new MyPartDao(dbp, random);
      MhealthDao mhealth = new MhealthDao(dbp, 100L);
      //signUp and signIn first user "123"
      String deviceRpid = myPart.registerDevice("123", "me2@gmail.com", "896", "MyHeart Counts iOS App",300L);
      Long userRpId1 = myPart.verifyEmail("me2@gmail.com",300L,deviceRpid,111L);
      Long deviceAppId1 = mhealth.createDeviceApp(100L,"$2a$16$ZChp8/nCBmf5BB/HXL2jmehjGJmXjcdGyI5Wn.8wjL.4zvKMMXb.e","password_bcryted",deviceRpid);
      Long mhUserProfId1 = mhealth.createMhUserProfile(userRpId1);
      mhealth.updateMhDeviceApp(deviceRpid, mhUserProfId1);
      myPart.createBaseConsent(300L,deviceRpid,"me2@gmail.com",new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime(),"all_qualified_researchers",null,null,1L);
    });
  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void testLeaveStudyAndSubsequentSignIn(TestContext context) {

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());

    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    String password = StringUtils.leftPad("123", 32, "a");
    client.post(8001, "localhost", "/mhc/api/v1/consent/dataSharing", sharingResponse -> {
      context.assertEquals(200, sharingResponse.statusCode());

      sharingResponse.bodyHandler(sharing -> {
        context.assertTrue(sharing.toString().contains("Data sharing has been changed"));
        client.get(8001, "localhost", "/mhc/api/v1/auth/withdraw", withdrawResponse -> {
          context.assertEquals(200, withdrawResponse.statusCode());
          withdrawResponse.bodyHandler(signOut -> {
            context.assertTrue(signOut.toString().contains("Withdrawn from the study."));
            client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse -> {
              context.assertEquals(412, signInResponse.statusCode());
              signInResponse.bodyHandler(signIn -> {
                context.assertFalse(signIn.toJsonObject().getBoolean("consented"));
                async.complete();
              });
            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .putHeader("Bridge-Session", "myToken123")
                .end("{\"username\":\"" + "123" + "\",\"study\":\"" + "cardiovascular" + "\",\"password\":\""
                + password + "\"}");

          });
        }).exceptionHandler(context::fail)
            .putHeader("Bridge-Session", "myToken123").end();
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "myToken123").end("{\"scope\":\"" + "no_sharing" + "\" }");

    verifyNoMoreInteractions(mailer);
  }

  // session token returning a deviceRpid which does not exist
  @Test
  public void testDataSharingInvalidScope(TestContext context) {

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());

    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/consent/dataSharing", sharingResponse -> {
      context.assertEquals(400, sharingResponse.statusCode());

      sharingResponse.bodyHandler(sharing -> {
        context.assertTrue(sharing.toString().contains("Invalid Scope."));
        async.complete();
      });

    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "myToken123").end("{\"scope\":\"" + "no_share" + "\" }");

    verifyNoMoreInteractions(mailer);

  }

  // session token returning a deviceRpid which does not exist
  // Therefore the authorization handler fails.
  @Test
  public void testSignOutInternalError(TestContext context) {

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "666").put("consented", true));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());

    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    client.get(8001, "localhost", "/mhc/api/v1/auth/withdraw", withdrawResponse -> {
      context.assertEquals(500, withdrawResponse.statusCode());
      withdrawResponse.bodyHandler(withdraw -> {
        context.assertTrue(withdraw.toString().contains("Not Withdrawn from the study"));
        async.complete();
      });

    }).exceptionHandler(context::fail)
        .putHeader("Bridge-Session", "myToken123").end();

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
