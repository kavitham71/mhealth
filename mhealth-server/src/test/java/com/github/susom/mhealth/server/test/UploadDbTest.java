package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.MyHeartCountsApi;
import com.github.susom.mhealth.server.apis.PortalServerApi;
import com.github.susom.mhealth.server.apis.SageApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import com.github.susom.mhealth.server.apis.UploadRequest;
import com.github.susom.mhealth.server.container.ParticipantPortal;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.mhealth.server.services.MhealthDao;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.GregorianCalendar;
import com.github.susom.vertx.base.Valid;
import org.apache.commons.io.FileUtils;
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
public class UploadDbTest {
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
      myPart.createBaseConsent(300L,deviceRpid,"me2@gmail.com",new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime(),"all_qualified_reserchers",null,null,0L);
    });
  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void testUpload(TestContext context) {

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");
    UploadRequest request = new UploadRequest();
    request.setName("decrypted-3.zip");
    request.setContentLength(1024);
    request.setContentMd5("6RQ57lzGqQV+SXHQFxZCFQ==");
    createFile("target/f1", 1024);

    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    client.post(8001, "localhost", "/mhc/api/v1/upload", uploadResponse -> {
      context.assertEquals(201, uploadResponse.statusCode());

      uploadResponse.bodyHandler(body -> {
        String bodyString = body.toString();

        JsonObject response = new JsonObject(bodyString);
        String Id = Valid.nonNull(response.getString("id"), "id cannot be null");
        String Type = Valid.nonNull(response.getString("type"),"type cannot be null");
        context.assertEquals(Type, "UploadSession");
        try {
          client.put(8001, "localhost", "/mhc/api/v1/upload/" + Id, uploadIdResponse -> {
            context.assertEquals(200, uploadIdResponse.statusCode());
            uploadIdResponse.bodyHandler(uploadId -> {
              client.post(8001, "localhost", "/mhc/api/v1/upload/" + Id + "/complete", uploadCompleteResponse -> {
                context.assertEquals(200, uploadCompleteResponse.statusCode());
                uploadCompleteResponse.bodyHandler(uploadComplete -> {
                  client.get(8001, "localhost", "/mhc/api/v1/upload/" + Id + "/status?study=cardiovascular",
                      uploadStatusResponse -> {
                        context.assertEquals(200, uploadStatusResponse.statusCode());
                        uploadStatusResponse.bodyHandler(uploadStatus -> {
                          context.assertTrue(uploadStatus.toString().contains("succeeded"));
                          async.complete();
                        });
                      }).exceptionHandler(context::fail)
                      .putHeader("Bridge-Session", "myToken123").end();

                });
              }).exceptionHandler(context::fail)
                  .putHeader("Bridge-Session", "myToken123")
                  .end();

            });
          }).exceptionHandler(context::fail).putHeader("content-type", "application/zip")
              .putHeader("Bridge-Session", "myToken123")
              .putHeader("User-Agent", "CardioHealth/9 CFNetwork/711.4.6 Darwin/14.5.0®")
              .end(Json.encode(FileUtils.readFileToString(new File("target/f1"))));
        } catch (Exception e) {
          System.out.println("Exception" + e.getMessage());
        }
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", "myToken123")
        .end(Json.encode(request));

    verifyNoMoreInteractions(mailer);
  }

  private static String createFile(String name, int length) {
    RandomAccessFile f = null;
    try {
      File file = new File(name);
      if (!file.exists()) {
        f = new RandomAccessFile(file, "rw");
        f.setLength(length);
      }
    } catch (Exception e) {
      System.err.println(e);
    }
    return name;
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

  public static byte[] getBytesFromFile(File file) throws IOException {
    InputStream is = new FileInputStream(file);

    // Get the size of the file
    long length = file.length();

    if (length > Integer.MAX_VALUE) {
      // File is too large
    }

    // Create the byte array to hold the data
    byte[] bytes = new byte[(int) length];

    // Read in the bytes
    int offset = 0;
    int numRead = 0;
    while (offset < bytes.length
        && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
      offset += numRead;
    }

    // Ensure all the bytes have been read in
    if (offset < bytes.length) {
      throw new IOException("Could not completely read file " + file.getName());
    }

    // Close the input stream and return bytes
    is.close();
    return bytes;
  }
}
