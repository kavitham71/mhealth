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
public class AuthenticationErrorDbTest {
  private Vertx vertx;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  private Builder dbb;
  @Mock
  private Mailer mailer;
  @Mock
  private JWTAuth jwt;
  @Mock
  SageApi sageApi;
  SecureRandom random;

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
  public void testConsentWithAuthenticationError(TestContext context) {

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    Async async = context.async();
    String password = StringUtils.leftPad("123", 32, "a");

    // set up the database to get past signUp and SignIn dbb.transact(new DbRun() {
    dbb.transact(dbp -> {

      MyPartDao myPart = new MyPartDao(dbp, random);
      MhealthDao mhealth = new MhealthDao(dbp, 300L);
      String deviceRpid = myPart.registerDevice("123", "me2@gmail.com", "345", "MyHeart Counts iOS App",300L);
      myPart.verifyEmail("me2@gmail.com",300L,deviceRpid,null);
      mhealth.createDeviceApp(100L,"$2a$16$ZChp8/nCBmf5BB/HXL2jmehjGJmXjcdGyI5Wn.8wjL.4zvKMMXb.e","password_bcryted",deviceRpid);
    });

    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/auth/signIn", signInResponse ->

    {
      context.assertEquals(412, signInResponse.statusCode());

      signInResponse.bodyHandler(sessionInfoBody -> {
        System.out.println("SessionInfo: " + sessionInfoBody);
        JsonObject sessionInfoJson = new JsonObject(sessionInfoBody.toString());
        context.assertTrue(sessionInfoJson.getBoolean("authenticated"));

        client.post(8001, "localhost", "/mhc/api/v1/consent", consentResponse -> {
          context.assertEquals(401, consentResponse.statusCode());

          consentResponse.bodyHandler(response -> {
            context.assertTrue(response.toString().contains("Session expired"));
            async.complete();
          });
        }).exceptionHandler(context::fail).putHeader("Bridge-Session", "myToken123")
            .putHeader("content-type", "application/json").end("{\"name\":\"" + "me2@gmail.com"
            + "\",\"scope\":\"ALL_QUALIFIED_RESEARCHERS\",\"birthdate\":\"12-30-2011\"}");
      });

    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .end("{\"username\":\"" + "123" + "\",\"study\":\"" + "cardiovascular" + "\",\"password\": \"" + password
            + "\"}");

    verifyNoMoreInteractions(mailer);

    dbb.transactAsync(dbp -> {
      return dbp.get().toSelect("select 'hi'")
          .<JsonObject>queryMany(r -> new JsonObject().put("message", r.getStringOrEmpty(1)));
    }, result -> System.out.println(result.result().get(0).getString("message")));
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
          return false;
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
