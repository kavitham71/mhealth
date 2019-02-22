package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.MyHeartCountsApi;
import com.github.susom.mhealth.server.apis.PortalServerApi;
import com.github.susom.mhealth.server.apis.ResearcherApi;
import com.github.susom.mhealth.server.apis.SageApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import com.github.susom.mhealth.server.container.ResearcherPortal;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.mhealth.server.services.MhealthDao;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.vertx.base.AuthenticatedUser;
import com.github.susom.vertx.base.Security;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import javax.annotation.Untainted;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class DataDeliveryDbTest {
  private Vertx vertx;
  private ResearcherPortal researchPortal;
  private ResearcherApi researcherApi;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  private Builder dbb;
  private String currentUser;

  @Mock
  private JWTAuth jwt;
  @Mock
  private Mailer mailer;
  @Mock
  SageApi sageApi;
  @Mock
  Security security;

  @Before
  public void setUp(TestContext context) throws Exception {
    MockitoAnnotations.initMocks(this);

    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    vertx = Vertx.vertx();
    String propertiesFile = System.getProperty("local.properties", "../local.properties");
    Config config = Config.from().systemProperties()
        .value("mh.upload.url", "http://loclhost:8080/researcherApi/api/v1/fileUpload/").propertyFile(propertiesFile)
        .get();
    realDbb = DatabaseProviderVertx.pooledBuilder(vertx, config).withSqlParameterLogging()
        .withSqlInExceptionMessages();
    realDbp = realDbb.create();
    dbb = realDbp.fakeBuilder();

    SecureRandom random = new SecureRandom();

    Router root = Router.router(vertx);
    @Untainted HashMap<String,String> map = new HashMap<String,String>();
    researchPortal = new ResearcherPortal(dbb, random, config,security,map);
    // Provide authenticated user for the test
    Router researchPortalRouter = Router.router(vertx);
    researchPortalRouter.route().handler(rc -> {

      rc.setUser(
          new AuthenticatedUser(currentUser, currentUser, currentUser + " Display", new HashSet<>())
      );
      rc.next();
    });
    root.mountSubRouter("/researcher", researchPortal.addToRouter(vertx, researchPortalRouter));
    vertx.createHttpServer().requestHandler(root::accept).listen(8001, context.asyncAssertSuccess());
    researcherApi = new ResearcherApi(dbb, random, config);
    root.mountSubRouter("/server", new PortalServerApi(dbb, random, mailer, config,sageApi).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8002, context.asyncAssertSuccess());
    root.mountSubRouter("/researcherApi", researcherApi.router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8003, context.asyncAssertSuccess());
    TwentyThreeAndMeReal twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);
    TwentyThreeAndMeApi twentyThree = new TwentyThreeAndMeApi(dbb, random, config, twentyThreeAndMe);
    root.mountSubRouter("/mhc", new MyHeartCountsApi(dbb, random, jwt, config, vertx, twentyThree).router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8004, context.asyncAssertSuccess());

    // set up the database to get past signUp and SignIn
    dbb.transact(dbp -> {
    
      byte[] data = javax.xml.bind.DatatypeConverter.parseHexBinary("e04fd020ea3a6910a2d808002b30309d");
     
      //first user device_rpid = 123
      MyPartDao myPart = new MyPartDao(dbp, random);
      MhealthDao mhealth = new MhealthDao(dbp, 100L);
      //signUp and signIn first user "123"
      String deviceRpid = myPart.registerDevice("123", "me2@gmail.com", "896", "MyHeart Counts iOS App",300L);
      Long userRpId1 = myPart.verifyEmail("me2@gmail.com",300L,deviceRpid,111L);
      Long deviceAppId1 = mhealth.createDeviceApp(100L,"$2a$16$ZChp8/nCBmf5BB/HXL2jmehjGJmXjcdGyI5Wn.8wjL.4zvKMMXb.e","password_bcryted",deviceRpid);
      Long mhUserProfId1 = mhealth.createMhUserProfile(userRpId1);
      mhealth.updateMhDeviceApp(deviceRpid, mhUserProfId1);
      myPart.createBaseConsent(300L,deviceRpid,"me2@gmail.com",new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime(),"sponsors_and_partners",null,null,0L);
      mhealth.createFileUpload(random,100L,deviceRpid,data);
      mhealth.createFileUpload(random,100L,deviceRpid,data);
      mhealth.createFileUpload(random,100L,deviceRpid,data);
      mhealth.createFileUpload(random,100L,deviceRpid,data);
      mhealth.createFileUpload(random,100L,deviceRpid,data);
      //signUp and signIn second device "345"
      String deviceRpid2 = myPart.registerDevice("345", "me3@gmail.com", "678", "MyHeart Counts iOS App",300L);
      Long userRpId2 = myPart.verifyEmail("me3@gmail.com",300L,deviceRpid2,222L);
      Long deviceAppId2 =  mhealth.createDeviceApp(100L,"$2a$16$ZChp8/nCBmf5BB/HXL2jmehjGJmXjcdGyI5Wn.8wjL.4zvKMMXb.e","password_bcryted",deviceRpid2);
      Long mhUserProfId2 = mhealth.createMhUserProfile(userRpId2);
      mhealth.updateMhDeviceApp(deviceRpid2, mhUserProfId2);
      myPart.createBaseConsent(300L,deviceRpid2,"me3@gmail.com",new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime(),"all_qualified_researchers",null,null,0L);
      mhealth.createFileUpload(random,100L,deviceRpid2,data);
      mhealth.createFileUpload(random,100L,deviceRpid2,data);
      mhealth.createFileUpload(random,100L,deviceRpid2,data);
      mhealth.createFileUpload(random,100L,deviceRpid2,data);
      mhealth.createFileUpload(random,100L,deviceRpid2,data);
});
  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void DataDeliveryTestForSponsorsAndPartners(TestContext context) {
    currentUser = "testing1";

    User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("sub", "123").put("consented", true));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    vertx.getOrCreateContext().runOnContext(v ->
    researcherApi.uploadSequenceHandler(r -> {
      if (r.succeeded()) {
        client.post(8001, "localhost", "/researcher/api/v1/studies", studiesResponse -> {
          context.assertEquals(200, studiesResponse.statusCode());
          studiesResponse.bodyHandler(studies -> {
            JsonObject studiesArray = studies.toJsonObject();
            JsonArray studies1 = studiesArray.getJsonArray("studies");
            JsonObject study = studies1.getJsonObject(0);
            context.assertEquals("cardiovascular", study.getString("shortName"));
            client.post(8001, "localhost", "/researcher/api/v1/token/issue", tokenResponse -> {
              context.assertEquals(200, tokenResponse.statusCode());
              tokenResponse.bodyHandler(token -> {
                JsonObject token1 = new JsonObject(token.toString());
                String apiToken = token1.getString("token");
                QueryStringEncoder enc = new QueryStringEncoder("");
                enc.addParam("grant_type", "refresh_token");
                enc.addParam("refresh_token", apiToken);
                String encodedBody = enc.toString().substring(1);
                Buffer tokenBuf = Buffer.buffer();
                tokenBuf.appendString(encodedBody);
                client.post(8003, "localhost", "/researcherApi/api/v1/token", refreshTokenResponse -> {
                  context.assertEquals(200, refreshTokenResponse.statusCode());
                  refreshTokenResponse.bodyHandler(refreshToken -> {
                    JsonObject token2 = new JsonObject(refreshToken.toString());
                    String rToken = token2.getString("refresh_token");
                    String aToken = token2.getString("access_token");
                    client.getAbs("http://localhost:8003/researcherApi/api/v1/participants/", participantsResponse -> {
                      context.assertEquals(200, participantsResponse.statusCode());
                      participantsResponse.bodyHandler(participants -> {
                        JsonObject participant = new JsonObject(participants.toString());
                        JsonArray participantIds = participant.getJsonArray("Participants");
                        context.assertEquals(2, participantIds.size());
                        Long participantId = participantIds.getJsonObject(0).getLong("id");
                        Long sequence = participantIds.getJsonObject(0).getLong("sequence");
                        context.assertEquals(111L, participantId);
                        client.post(8001, "localhost", "/mhc/api/v1/consent/dataSharing", sharingResponse -> {
                          context.assertEquals(200, sharingResponse.statusCode());
                          client.getAbs("http://localhost:8003/researcherApi/api/v1/participants?sequence="
                              + sequence, participants1Response -> {
                            participants1Response.bodyHandler(participants1 -> {
                              JsonObject participant1 = new JsonObject(participants1.toString());
                              JsonArray participant1Ids = participant1.getJsonArray("Participants");
                              context.assertEquals(1, participant1Ids.size());
                              Long participant1Id = participant1Ids.getJsonObject(0).getLong("id");
                              context.assertEquals(111L, participant1Id);
                              client.getAbs("http://localhost:8003/researcherApi/api/v1/files?order=desc",
                                  filesUploadResponse -> {
                                    context.assertEquals(200, filesUploadResponse.statusCode());
                                    filesUploadResponse.bodyHandler(filesUpload -> {
                                      JsonObject filesUpld = new JsonObject(filesUpload.toString());
                                      JsonArray Urls = filesUpld.getJsonArray("dataUrls");
                                      context.assertTrue(Urls.size() == 10);
                                      JsonObject dataUrls1 = Urls.getJsonObject(1);
                                      Long[] sequence1 = new Long[1];
                                      sequence1[0] = dataUrls1.getLong("sequence");
                                      context.assertNotNull(dataUrls1.getLong("sequence"));
                                      client.getAbs(
                                          "http://localhost:8003/researcherApi/api/v1/files?since=" + sequence1[0],
                                          filesUpldResponse -> {
                                            context.assertEquals(200, filesUpldResponse.statusCode());
                                            filesUpldResponse.bodyHandler(fileUpld -> {
                                              JsonObject Upld = new JsonObject(fileUpld.toString());
                                              JsonArray Urlss = Upld.getJsonArray("dataUrls");
                                              JsonObject dataUrls = Urlss.getJsonObject(0);
                                              context.assertEquals(1, Urlss.size());
                                              context.assertNotNull(dataUrls.getLong("sequence"));
                                              context.assertNotNull(dataUrls.getLong("participantId"));
                                              context.assertEquals(222L, dataUrls.getLong("participantId"));
                                              async.complete();
                                            });
                              /*client.post(8003, "localhost", "/researcherApi/api/v1/token", token1Response -> {
                                context.assertEquals(200, token1Response.statusCode());
                                token1Response.bodyHandler(token12 -> {
                                  JsonObject token3 = new JsonObject(token12.toString());
                                  context.assertNotNull(token3.getString("refresh_token"));
                                  context.assertNotNull(token3.getString("access_token"));
                              async.complete();
                              });
                              }).exceptionHandler(context::fail)
                                  .putHeader("content-type", "application/x-www-form-urlencoded")
                                  .end(tokenBuf2);
                              });*/
                                          }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                                          .putHeader("Authorization", "Bearer " + aToken)
                                          .end();
                                    });
                                  }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                                  .putHeader("Authorization", "Bearer " + aToken)
                                  .end();
                            });
                          }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                              .putHeader("Authorization", "Bearer " + aToken)
                              .end();
                        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                            .putHeader("Bridge-Session", "myToken123").end(
                            "{\"scope\":\"" + "sponsors_and_partners" + "\" }");
                      });
                    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                        .putHeader("Authorization", "Bearer " + aToken)
                        .end();
                  });
                }).exceptionHandler(context::fail).putHeader("content-type", "application/x-www-form-urlencoded")
                    .end(tokenBuf);
                // MDC.clear();
              });
            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .end(new JsonObject().put("sunetId", "testing1").put("studyId", study.getLong("studyId")).encodePrettily());
          });
        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end(new JsonObject().put("sunetId", "testing1").put("pg", 1).encodePrettily());
      } else {
        context.fail();
      }
      // MDC.clear();
    })
    );
  }

  @Test
  public void DataDeliveryTestForAllQualifiedResearchers(TestContext context) {
    currentUser = "testing2";

    /*User user = mock(User.class);
    when(user.principal()).thenReturn(new JsonObject().put("studyId", "1").put("sunetId", "ritikam"));
    doAnswer(callback(user, 1)).when(jwt).authenticate(any(), any());
    when(jwt.generateToken(any(), any())).thenReturn("mytoken123");*/
    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    vertx.getOrCreateContext().runOnContext(v ->
    researcherApi.uploadSequenceHandler(r -> {
      if (r.succeeded()) {
        client.post(8001, "localhost", "/researcher/api/v1/studies", studiesResponse -> {
          context.assertEquals(200, studiesResponse.statusCode());
          studiesResponse.bodyHandler(studies -> {
            JsonObject studyArray = studies.toJsonObject();
            JsonArray studies1 = studyArray.getJsonArray("studies");
            JsonObject study = studies1.getJsonObject(0);
            context.assertEquals("cardiovascular", study.getString("shortName"));
            client.post(8001, "localhost", "/researcher/api/v1/token/issue", tokenResponse -> {
              context.assertEquals(200, tokenResponse.statusCode());
              tokenResponse.bodyHandler(token -> {
                JsonObject token1 = new JsonObject(token.toString());
                String apiToken = token1.getString("token");
                QueryStringEncoder enc = new QueryStringEncoder("");
                enc.addParam("grant_type", "refresh_token");
                enc.addParam("refresh_token", apiToken);
                String encodedBody = enc.toString().substring(1);
                Buffer tokenBuf = Buffer.buffer();
                tokenBuf.appendString(encodedBody);
                client.post(8003, "localhost", "/researcherApi/api/v1/token", refreshTokenResponse -> {
                  context.assertEquals(200, refreshTokenResponse.statusCode());
                  refreshTokenResponse.bodyHandler(refreshToken -> {
                    JsonObject token2 = new JsonObject(refreshToken.toString());
                    String rToken = token2.getString("refresh_token");
                    String aToken = token2.getString("access_token");
                    client.getAbs("http://localhost:8003/researcherApi/api/v1/participants", participantsResponse -> {
                      context.assertEquals(200, participantsResponse.statusCode());
                      participantsResponse.bodyHandler(participants -> {
                        JsonObject participant = new JsonObject(participants.toString());
                        JsonArray participantIds = participant.getJsonArray("Participants");
                        Long participantId = participantIds.getJsonObject(0).getLong("id");
                        context.assertEquals(1, participantIds.size());
                        context.assertEquals(222L, participantId);
                        Long sequence[] = new Long[1];
                        client.getAbs("http://localhost:8003/researcherApi/api/v1/files/?order=desc",
                            filesUploadResponse -> {
                          context.assertEquals(200, filesUploadResponse.statusCode());
                          filesUploadResponse.bodyHandler(filesUpload -> {
                            JsonObject filesUpld = new JsonObject(filesUpload.toString());
                            JsonArray Urls = filesUpld.getJsonArray("dataUrls");
                            context.assertTrue(Urls.size() == 5);
                            JsonObject dataUrls1 = Urls.getJsonObject(4);
                            sequence[0] = dataUrls1.getLong("sequence");
                            context.assertNotNull(dataUrls1.getLong("sequence"));
                            client.getAbs("http://localhost:8003/researcherApi/api/v1/files/?since=" + sequence[0],
                                filesUpldResponse -> {
                              context.assertEquals(200, filesUpldResponse.statusCode());
                              filesUpldResponse.bodyHandler(fileUpld -> {
                                JsonObject Upld = new JsonObject(fileUpld.toString());
                                JsonArray Urlss = Upld.getJsonArray("dataUrls");
                                context.assertEquals(4, Urlss.size());
                                JsonObject dataUrls = Urlss.getJsonObject(0);
                                Long sequence2 = dataUrls.getLong("sequence");
                                context.assertNotNull(sequence2);
                                context.assertNotNull(dataUrls.getLong("participantId"));
                                async.complete();
                                // context.assertEquals(222L, dataUrls.getLong("participantId"));
                                /*client.getAbs("http://localhost:8003/researcherApi/api/v1/file?sequence=" + sequence2,
                                    token1Response -> {
                                  context.assertEquals(200, token1Response.statusCode());
                                  token1Response.bodyHandler(buf -> {
                                    byte[] decrypted = buf.getBytes();
                                    try {
                                      FileUtils.writeByteArrayToFile(new File("decrypted-" + "test1" + ".zip"),
                                          decrypted);
                                    } catch (Exception e) {
                                    }
                                    async.complete();
                                  });
                                }).exceptionHandler(context::fail)
                                    .putHeader("Authorization", "Bearer " + aToken)
                                    .putHeader("content-type", "application/x-www-form-urlencoded")
                                    .end();*/
                              });
                            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                                .putHeader("Authorization", "Bearer " + aToken)
                                .end();
                          });
                        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                            .putHeader("Authorization", "Bearer " + aToken)
                            .end();

                      });
                    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                        .putHeader("Authorization", "Bearer " + aToken)
                        .end();
                  });
                }).exceptionHandler(context::fail).putHeader("content-type", "application/x-www-form-urlencoded")
                    .end(tokenBuf);
                // MDC.clear();
              });
            }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
                .end(new JsonObject().put("sunetId", "testing2").put("studyId", study.getLong("studyId")).encodePrettily());
          });
        }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
            .end(new JsonObject().put("sunetId", "testing2").put("pg", 1).encodePrettily());
      } else {
        context.fail();
      }
      // MDC.clear();
    })
    );
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
