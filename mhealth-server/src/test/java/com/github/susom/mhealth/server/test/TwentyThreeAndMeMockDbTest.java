package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.GenomeData;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.Profile;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.RefreshResult;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.UserResult;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

/**
 * Basic tests for enrolling a participant in MyHeart Counts.
 */
@RunWith(VertxUnitRunner.class)
public class TwentyThreeAndMeMockDbTest {
  private Vertx vertx;
  private TwentyThreeAndMeApi myApi;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;
  private Builder dbb;
  @Mock
  private TwentyThreeAndMe twentyThreeAndMe;
  @Mock
  private RoutingContext routingContext;
  @Mock
  private HttpServerResponse response;

  @Before
  public void setUp(TestContext context) throws Exception {
    MockitoAnnotations.initMocks(this);

    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    vertx = Vertx.vertx();
    String propertiesFile = System.getProperty("local.properties", "../local.properties");
    Config config = Config.from().systemProperties().value("genotyped.call.limit", "1").propertyFile(propertiesFile)
        .get();
    realDbb = DatabaseProviderVertx.pooledBuilder(vertx, config).withSqlParameterLogging()
        .withSqlInExceptionMessages();
    realDbp = realDbb.create();
    dbb = realDbp.fakeBuilder();

    SecureRandom random = new SecureRandom();

    Router root = Router.router(vertx);
    myApi = new TwentyThreeAndMeApi(dbb, random, config, twentyThreeAndMe);
    root.mountSubRouter("/mhc", myApi.router(vertx));
    vertx.createHttpServer().requestHandler(root::accept).listen(8001, context.asyncAssertSuccess());

  }

  @After
  public void tearDown(TestContext context) {
    realDbp.rollbackAndClose();
    realDbb.close();
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void test23andmeUserAndRefreshTokenFailure(TestContext context) {

    Async async = context.async();

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(eq(200))).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    RefreshResult refresh = mock(RefreshResult.class);

    refresh.accessToken = "bToken1";

    refresh.refreshToken = "refreshToken";

    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken1"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>((h -> h.handle(Future.succeededFuture(refresh))))));
    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken1"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>(h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 401 + ",\"message\":"
            + "\"Unauthorized\"" + "}")))));
    Date date = new Date(2 / 14 / 2016);
    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg, genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId1").argString(
          "bToken1").argString("rToken1").argBoolean(false).argString("statusKey1")
          .argString("profileId1").argBoolean(false).argDate(date).argDate(date).argInteger(0).argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId1").argString(
          "profileId1").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {
          verify(twentyThreeAndMe).refreshToken(eq("rToken1"), any());
          verify(twentyThreeAndMe).userInfo(eq("bToken1"), any());
          verifyNoMoreInteractions(twentyThreeAndMe);
          if (resultHandler.succeeded()) {
            myApi.findTheDownloadStatus("statusKey1", routingContext, resultHandler2 -> {
              if (resultHandler2.succeeded()) {
                verify(response).setStatusCode(eq(200));
                ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
                verify(response).setStatusMessage(argument.capture());
                context.assertTrue(argument.getValue().toString().contains("pending"));
                async.complete();
              } else {
                context.fail();
              }
            });
          }
        })
    );
  }

  @Test
  public void test23andmeSuccessScenario(TestContext context) {

    Async async = context.async();

    RefreshResult refresh = mock(RefreshResult.class);
    refresh.accessToken = "accessToken";
    refresh.refreshToken = "refreshToken";

    UserResult user = mock(UserResult.class);
    user.id = "userId2";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId2";
    user.profiles.add(prof);

    GenomeData genome = mock(GenomeData.class);

    genome.genome = "This_is_fake_genome_data.";
    genome.id = "profileId2";

    TwentyThreeAndMeApi spy = spy(myApi);
    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken2"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>(h -> h.handle(Future.succeededFuture(user)))));
    doNothing().when(twentyThreeAndMe).geneticData(eq("profileId2"), eq("bToken2"),
        argThat(new Callback<Handler<AsyncResult<GenomeData>>>(h -> {
          h.handle(Future.succeededFuture(genome));
        })));
    doNothing().when(spy).getGenomeData(eq("userId2"), eq("profileId2"), eq("bToken2"), argThat(
        new Callback<Handler<AsyncResult<GenomeData>>>(h -> {
          h.handle(Future.succeededFuture(genome));
          async.complete();
        })));

    vertx.getOrCreateContext().runOnContext(v ->
      spy.callTwentyThreeAndMe("userId2", "bToken2", "profileId2", "rToken2", routingContext, resultHandler -> {

        verify(twentyThreeAndMe).userInfo(eq("bToken2"), any());
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(response).setStatusMessage(argument.capture());
        context.assertTrue(argument.getValue().toString().contains("pending"));
        context.assertTrue(argument.getValue().toString().contains("statusKey"));
      })
    );
  }

  @Test
  public void test23andmeUserInfoReturning308Code(TestContext context) {

    Async async = context.async();

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken3"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>(h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 308 + ",\"message\":"
            + "\"Permanent Redirect \"" + "}")))));

    myApi.callTwentyThreeAndMe("userId3", "bToken3", "profileId3", "rToken3", routingContext, resultHandler -> {

      verify(twentyThreeAndMe).userInfo(eq("bToken3"), any());
      ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
      verify(response).setStatusMessage(argument.capture());
      context.assertTrue(argument.getValue().toString().contains("308"));
      verifyNoMoreInteractions(twentyThreeAndMe);

      if (resultHandler.failed()) {
        context.assertTrue(resultHandler.cause().toString().contains("Error calling 23andme user api"));
        async.complete();
      }
    });

  }

  @Test
  public void test23andmeWhenUserInfoReturns401(TestContext context) {

    Async async = context.async();

    RefreshResult refresh = mock(RefreshResult.class);
    refresh.accessToken = "accessToken";
    refresh.refreshToken = "refreshToken";

    UserResult user = mock(UserResult.class);
    user.id = "userId4";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId4";
    user.profiles.add(prof);

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken4"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 401 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))), (h -> h.handle(Future.succeededFuture(user))))));

    myApi.callTwentyThreeAndMe("userId4", "bToken4", "profileId4", "rToken4", routingContext, resultHandler -> {
      verify(twentyThreeAndMe).userInfo(eq("bToken4"), any());
      verifyNoMoreInteractions(twentyThreeAndMe);
      JsonObject status = new JsonObject();
      status.put("status", "failed");
      status.put("errorCode", 401);
      status.put("message", "Unauthorized");
      verify(response).setStatusMessage(status.encode());
      async.complete();
    });

  }

  @Test
  public void test23andmeTestDownloadHandler(TestContext context) {

    Async async = context.async();
//set up the database

    UserResult user = mock(UserResult.class);
    user.id = "userId5";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId5";
    user.profiles.add(prof);

    GenomeData genome = mock(GenomeData.class);

    genome.genome = "This_is_fake_genome_data.";
    genome.id = "profileId5";

    doNothing().when(twentyThreeAndMe).geneticData(eq("profileId5"), eq("bToken5"),
        argThat(new Callback<Handler<AsyncResult<GenomeData>>>(h -> h.handle(Future.succeededFuture(genome)))));

    Date date = new Date(2 / 14 / 2016);

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg, genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId5").argString(
          "bToken5").argString("rToken5").argBoolean(false).argString("statusKey5")
          .argString("profileId5").argBoolean(true).argDateNowPerDb().argDateNowPerDb().argInteger(0).argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId5").argString(
          "profileId5").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {

          verify(twentyThreeAndMe).geneticData(eq("profileId5"), eq("bToken5"), any());
          verifyNoMoreInteractions(twentyThreeAndMe);

          if (resultHandler.succeeded()) {
            async.complete();
          }
        })
    );
  }

  @Test
  //The client is not genotyped and it is less than a day since getGenotyped was called
  public void test23andmeTestDownloadHandlerWhenNotGenotyped(TestContext context) {

    Async async = context.async();
//set up the database

    UserResult user = mock(UserResult.class);
    user.id = "userId6";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId6";
    user.profiles.add(prof);

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    Date date = new Date(2 / 14 / 2016);

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg,genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId6").argString(
          "bToken6")
          .argString("rToken6").argBoolean(false).argString("statusKey6")
          .argString("profileId6").argBoolean(false).argDateNowPerDb().argDateNowPerDb().argInteger(0)
          .argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId6").argString(
          "profileId6").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {

          if (resultHandler.succeeded()) {
            myApi.findTheDownloadStatus("statusKey6", routingContext, resultHandler2 -> {
              if (resultHandler2.succeeded()) {
                verify(response).setStatusCode(eq(200));
                ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
                verify(response).setStatusMessage(argument.capture());
                context.assertTrue(argument.getValue().toString().contains("pending"));
                async.complete();
              } else {
                context.fail();
              }
            });
          }
        })
    );
  }

  @Test
  //DownloadHandler handling 3 clients
  public void test23andmeTestDownloadHandlerMultipleClients(TestContext context) {

    Async async = context.async();
//set up the database

    UserResult user1 = mock(UserResult.class);
    user1.id = "userId7";
    user1.profiles = new ArrayList<Profile>();
    Profile prof1 = new Profile();
    prof1.genotyped = false;
    prof1.id = "profileId7";
    user1.profiles.add(prof1);

    UserResult user2 = mock(UserResult.class);
    user2.id = "userId8";
    user2.profiles = new ArrayList<Profile>();
    Profile prof2 = new Profile();
    prof2.genotyped = true;
    prof2.id = "profileId8";
    user2.profiles.add(prof2);

    UserResult user3 = mock(UserResult.class);
    user3.id = "userId9";
    user3.profiles = new ArrayList<Profile>();
    Profile prof3 = new Profile();
    prof3.genotyped = true;
    prof3.id = "profileId9";
    user3.profiles.add(prof3);

    GenomeData genome1 = mock(GenomeData.class);

    genome1.genome = "This_is_fake_genome_data.";
    genome1.id = "profileId7";

    GenomeData genome2 = mock(GenomeData.class);

    genome2.genome = "This_is_fake_genome_data.";
    genome2.id = "profileId8";

    GenomeData genome3 = mock(GenomeData.class);

    genome3.genome = "This_is_fake_genome_data.";
    genome3.id = "profileId9";

    RefreshResult refresh1 = mock(RefreshResult.class);
    refresh1.accessToken = "bToken8";
    refresh1.refreshToken = "refreshToken81";

    RefreshResult refresh2 = mock(RefreshResult.class);
    refresh2.accessToken = "bToken7";
    refresh2.refreshToken = "refreshToken7";

    Date date = new Date(2 / 9 / 2016);

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    JsonObject status = new JsonObject();
    status.put("status", "complete");

    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken7"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>(h -> h.handle(Future.succeededFuture(refresh2)))));

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken7"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.succeededFuture(user1))))));


    doNothing().when(twentyThreeAndMe).geneticData(eq("profileId8"), eq("bToken8"),
        argThat(new Callback<Handler<AsyncResult<GenomeData>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 401 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))), (h -> {
          h.handle(Future.succeededFuture(genome2));
          myApi.findTheDownloadStatus("statusKey8", routingContext, resultHandler2 -> {
            if (resultHandler2.succeeded()) {
              async.complete();
            }
          });
        }))));

    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken8"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>(h -> h.handle(Future.succeededFuture(refresh1)))));

    doNothing().when(twentyThreeAndMe).geneticData(eq("profileId9"), eq("bToken9"),
        argThat(new Callback<Handler<AsyncResult<GenomeData>>>(h -> {
          h.handle(Future.succeededFuture(genome3));
          myApi.findTheDownloadStatus("statusKey9", routingContext, resultHandler2 -> {

          });
        })));

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg,genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId7").argString(
          "bToken7")
          .argString("rToken7").argBoolean(false).argString("statusKey7")
          .argString("profileId7").argBoolean(false).argDate(date).argDateNowPerDb().argInteger(0)
          .argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId7").argString(
          "profileId7").update(1);

      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg,genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId8").argString(
          "bToken8")
          .argString("rToken8").argBoolean(false).argString("statusKey8")
          .argString("profileId8").argBoolean(true).argDate(date).argDate(date).argInteger(0)
          .argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId8").argString(
          "profileId8").update(1);

      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg,genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId9").argString(
          "bToken9")
          .argString("rToken9").argBoolean(false).argString("statusKey9")
          .argString("profileId9").argBoolean(true).argDate(date).argDate(date).argInteger(0)
          .argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId9").argString(
          "profileId9").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {

          if (resultHandler.succeeded()) {
            context.assertTrue(resultHandler.result().contains("Successfully completed download handler."));
            verify(twentyThreeAndMe, atMost(1)).refreshToken(eq("rToken7"), any());
            verify(twentyThreeAndMe, atMost(1)).userInfo(eq("bToken7"), any());
            verify(twentyThreeAndMe, atMost(2)).geneticData(eq("profileId8"), eq("bToken8"), any());
            verify(twentyThreeAndMe, atMost(1)).refreshToken(eq("rToken8"), any());
            verify(twentyThreeAndMe, atMost(1)).geneticData(eq("profileId9"), eq("bToken9"), any());
            verify(response, atMost(3)).setStatusMessage(status.encode());
            verifyNoMoreInteractions(twentyThreeAndMe);
          } else if (resultHandler.failed()) {
            context.fail();
          }
        })
    );
  }

  @Test
  public void test23andmeWhenGetGenotypedLimitIsExceeded(TestContext context) {

    Async async = context.async();

    RefreshResult refresh = mock(RefreshResult.class);
    refresh.accessToken = "accessToken";
    refresh.refreshToken = "refreshToken";

    UserResult user = mock(UserResult.class);
    user.id = "userId10";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = false;
    prof.id = "profileId10";
    user.profiles.add(prof);

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken10"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 401 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))), (h -> h.handle(Future.succeededFuture(user))))));

    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken10"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>(h -> h.handle(Future.succeededFuture(refresh)))));
    doNothing().when(twentyThreeAndMe).refreshToken(eq("refreshToken"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>(h -> h.handle(Future.succeededFuture(refresh)))));

    Date date = new Date(2 / 14 / 2016);

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg,genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId10").argString(
          "bToken10")
          .argString("rToken10").argBoolean(false).argString("statusKey10")
          .argString("profileId10").argBoolean(false).argDate(date).argDate(date).argInteger(0)
          .argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId10").argString(
          "profileId10").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {
          InOrder order = inOrder(twentyThreeAndMe);
          order.verify(twentyThreeAndMe).refreshToken(eq("rToken10"), any());
          order.verify(twentyThreeAndMe).userInfo(eq("bToken10"), any());
          // order.verify(twentyThreeAndMe).refreshToken(eq("rToken10"), any());
          //  order.verify(twentyThreeAndMe).userInfo(eq("bToken10"), any());
          if (resultHandler.succeeded()) {
            // now we call downloadHandler again. This time when userInfo is called the genome call limit is exceeded
            myApi.twentyThreeAndMeDownloadHandler(resultHandler1 -> {
              //order.verify(twentyThreeAndMe).refreshToken(eq("refreshToken"), any());
              //order.verify(twentyThreeAndMe).userInfo(eq("bToken10"), any());
              if (resultHandler1.succeeded()) {
                order.verifyNoMoreInteractions();
                //retrieve the pending_error_msg from database it should say genotyped call limit exceede               
                myApi.findTheDownloadStatus("statusKey10", routingContext, result1 -> {
                  if (result1.succeeded()) {
                    verify(response).setStatusCode(eq(500));
                    ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
                    verify(response).setStatusMessage(argument.capture());
                    context.assertTrue(argument.getValue().toString().contains("failed"));
                    async.complete();
                  } else {
                    context.fail();
                  }

                });

              } else {
                context.fail();
              }
            });

          } else {
            context.fail();
          }
        })
    );
  }

  @Test
  public void test23andmeWhenUserInfoReturns404(TestContext context) {

    Async async = context.async();

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken11"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 404 + ",\"message\":"
            + "\"Not Found\"" + "}"))))));

    myApi.callTwentyThreeAndMe("userId11", "bToken11", "profileId11", "rToken11", routingContext, resultHandler -> {

      if (resultHandler.failed()) {

        InOrder order = inOrder(twentyThreeAndMe, response);
        order.verify(twentyThreeAndMe).userInfo(eq("bToken11"), any());
        JsonObject status = new JsonObject();
        status.put("status", "failed");
        status.put("errorCode", 404);
        status.put("message", "Not Found");
        order.verify(response).setStatusMessage(status.encode());
        order.verifyNoMoreInteractions();
        async.complete();
      } else {
        context.fail();
      }
    });

  }

  @Test
  public void test23andmeTestDownloadHandleWhenRrefreshTokenGives404(TestContext context) {

    Async async = context.async();

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(404)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    /*doNothing().when(twentyThreeAndMe).userInfo(eq("bToken12"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 401 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))))));*/

    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken12"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 404 + ",\"message\":"
            + "\"Not Found\"" + "}"))))));

    Date date = new Date(2 / 14 / 2016);

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg, genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId12").argString(
          "bToken12").argString("rToken12").argBoolean(false).argString("statusKey12")
          .argString("profileId12").argBoolean(false).argDate(date).argDate(date).argInteger(0).argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId12").argString(
          "profileId12").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {
          verify(twentyThreeAndMe).refreshToken(eq("rToken12"), any());
          //verify(twentyThreeAndMe).userInfo(eq("bToken12"), any());
          verifyNoMoreInteractions(twentyThreeAndMe);

          if (resultHandler.succeeded()) {
            myApi.findTheDownloadStatus("statusKey12", routingContext, result1 -> {
              if (result1.succeeded()) {
                verify(response).setStatusCode(eq(200));
                ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
                verify(response).setStatusMessage(argument.capture());
                context.assertTrue(argument.getValue().toString().contains("pending"));
                async.complete();
              } else {
                context.fail();
              }
            });
          } else {
            context.fail();
          }
        })
    );
  }

  @Test
  public void test23andmeTestDownloadHandlerWhenGeneticDataFailsTheFirstTime(TestContext context) {
    Async async = context.async();
//set up the database

    UserResult user = mock(UserResult.class);
    user.id = "userId13";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId13";
    user.profiles.add(prof);

    GenomeData genome = mock(GenomeData.class);

    genome.genome = "This_is_fake_genome_data.";
    genome.id = "profileId13";

    doNothing().when(twentyThreeAndMe).geneticData(eq("profileId13"), eq("bToken13"),
        argThat(new Callback<Handler<AsyncResult<GenomeData>>>((h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 404 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))), (h -> h.handle(Future.failedFuture("{\"statusCode\":"
            + 404 + ",\"message\":"
            + "\"Unauthorized\"" + "}"))), (h -> h.handle(Future.succeededFuture(genome))))));

    Date date = new Date(2 / 14 / 2016);

    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg, genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId13").argString(
          "bToken13").argString("rToken13").argBoolean(false).argString("statusKey13")
          .argString("profileId13").argBoolean(true).argDateNowPerDb().argDateNowPerDb().argInteger(0).argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId13").argString(
          "profileId13").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {
          verify(twentyThreeAndMe, atMost(1)).geneticData(eq("profileId13"), eq("bToken13"), any());
          if (resultHandler.succeeded()) {
            myApi.twentyThreeAndMeDownloadHandler(resultHandler2 -> {
              if (resultHandler2.succeeded()) {
                myApi.twentyThreeAndMeDownloadHandler(resultHandler3 -> {
                  verifyNoMoreInteractions(twentyThreeAndMe);
                  if (resultHandler3.succeeded()) {
                    async.complete();
                  }
                });
              }
            });
          }
        })
    );
  }

  @Test
  public void test23andmeWhenUserIdIsIncorrect(TestContext context) {

    Async async = context.async();

    UserResult user = mock(UserResult.class);
    user.id = "userId14";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = true;
    prof.id = "profileId14";
    user.profiles.add(prof);

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(400)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken14"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.succeededFuture(user))))));

    myApi.callTwentyThreeAndMe("userId13", "bToken14", "profileId14", "rToken14", routingContext, resultHandler -> {

      if (resultHandler.failed()) {
        verify(twentyThreeAndMe).userInfo(eq("bToken14"), any());
        verifyNoMoreInteractions(twentyThreeAndMe);
        async.complete();
      } else {
        context.fail();
      }
    });

  }

  @Test
  public void testDownloadStatusWhenNotGenotyoed(TestContext context) {

    Async async = context.async();

    UserResult user = mock(UserResult.class);
    user.id = "userId15";
    user.profiles = new ArrayList<Profile>();
    Profile prof = new Profile();
    prof.genotyped = false;
    prof.id = "profileId15";
    user.profiles.add(prof);

    RefreshResult refresh = mock(RefreshResult.class);
    refresh.accessToken = "accessToken";
    refresh.refreshToken = "refreshToken";

    when(routingContext.response()).thenReturn(response);
    when(response.setStatusCode(200)).thenReturn(response);
    when(response.setStatusMessage(anyString())).thenReturn(response);

    doNothing().when(twentyThreeAndMe).userInfo(eq("bToken15"),
        argThat(new Callback<Handler<AsyncResult<UserResult>>>((h -> h.handle(Future.succeededFuture(user))))));
    doNothing().when(twentyThreeAndMe).refreshToken(eq("rToken15"),
        argThat(new Callback<Handler<AsyncResult<RefreshResult>>>((h -> h.handle(Future.succeededFuture(refresh))))));
    Date date = new Date(2 / 14 / 2016);
    dbb.transact(dbp -> {
      dbp.get().toUpdate("insert into tm_user_info (user_id, bearer_token, refresh_token,download_status,"
          + "status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
          + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,"
          + "pending_error_msg, genome_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").argString("userId15").argString(
          "bToken15").argString("rToken15").argBoolean(false).argString("statusKey15")
          .argString("profileId15").argBoolean(false).argDate(date).argDateNowPerDb().argInteger(0).argInteger(0)
          .argInteger(0).argString(null).argInteger(0).argString(null).argDate(date).update(1);
      dbp.get().toUpdate("insert into tm_download (user_id,profile_id) values (?,?)").argString("userId15").argString(
          "profileId15").update(1);
    });

    vertx.getOrCreateContext().runOnContext(v ->
        myApi.twentyThreeAndMeDownloadHandler(resultHandler -> {
          verify(twentyThreeAndMe, atMost(1)).refreshToken(eq("rToken15"), any());
          verify(twentyThreeAndMe, atMost(1)).userInfo(eq("bToken15"), any());
          myApi.findTheDownloadStatus("statusKey15", routingContext, resultHandler2 -> {
            ArgumentCaptor<String> argument2 = ArgumentCaptor.forClass(String.class);
            verify(response).setStatusMessage(argument2.capture());
            JsonObject result1 = new JsonObject(argument2.getValue().toString());
            String st = result1.getString("status");
            if (st.equals("pending")) {
              async.complete();
            }
          });
        })
    );
  }
}
