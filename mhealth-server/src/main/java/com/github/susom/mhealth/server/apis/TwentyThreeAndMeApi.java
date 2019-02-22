package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.Sql;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.Profile;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.RefreshResult;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe.UserResult;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.Iterator;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents our local implementation of an API to support functionality required for
 * supporting 23AndMe
 */

public class TwentyThreeAndMeApi {
  private static final Logger log = LoggerFactory.getLogger(TwentyThreeAndMeApi.class);
  private final Builder dbb;
  private final TwentyThreeAndMe twentyThreeAndMe;
  private final SecureRandom secureRandom;
  private final Config config;
  private Integer genomeDataLimit = 4;
  private Integer genotypedLimit = 4;

  public TwentyThreeAndMeApi(Builder dbb, SecureRandom secureRandom, Config config,
                             TwentyThreeAndMe twentyThreeAndMe) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.twentyThreeAndMe = twentyThreeAndMe;
    this.config = config;
    if (config.getInteger("genome.data.call.limit") != null) {
      this.genomeDataLimit = config.getInteger("genome.data.call.limit");
    }
    if (config.getInteger("genotyped.call.limit") != null) {
      this.genotypedLimit = config.getInteger("genotyped.call.limit");
    }
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    MetricsHandler metricsHandler =
        new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests"));
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    // These also do not currently require authentication. They are intended to
    // facilitate downloading of a user's 23andMe genetic data to our server.
    router.post("/api/v1/23andme").handler(metricsHandler);
    router.post("/api/v1/23andme").handler(smallBodyHandler);
    router.post("/api/v1/23andme").handler(twentyThreeAndMeHandler(vertx));

    router.get("/api/v1/23andme/:statusKey/status").handler(metricsHandler);
    router.get("/api/v1/23andme/:statusKey/status").handler(twentyThreeAndMeStatusHandler());

    return router;
  }

  public void twentyThreeAndMeDownloadHandler(Handler<AsyncResult<String>> resultHandler) {
    //access the 23AndMe api to download genetic data 

    dbb.transactAsync(dbp -> {
          //We check the download_error_code field it should not be set. Because if it is set it means we tried everything. And
          //what ever error code is there is the final error that the client needs to take care of.
          return dbp.get().toSelect(
              "select profile_id,user_id, bearer_token,genotyped,"
                  + "refresh_token,times_genome_data_called,"
                  + "times_get_genotyped_called"
                  + " from tm_user_info where download_status = ? "
                  + "and download_error_code = ?")
              .argBoolean(false).argInteger(0).<DownloadHandlerObject>queryMany(
                  (r) -> {
                    DownloadHandlerObject obj = new DownloadHandlerObject();
                    obj.setProfileId(r.getStringOrEmpty("profile_id"));
                    obj.setUserId(r.getStringOrEmpty("user_id"));
                    obj.setBearerToken(r.getStringOrEmpty("bearer_token"));
                    obj.setGenotyped(r.getBooleanOrNull("genotyped"));
                    obj.setrefreshToken(r.getStringOrEmpty("refresh_token"));
                    obj.setTimesGenomeDataCalled(r.getIntegerOrZero("times_genome_data_called"));
                    obj.setTimesGetGenotypedCalled(r.getIntegerOrZero("times_get_genotyped_called"));
                    return obj;
                  });

        },
        dbResult -> {
          //result[0]records the successful downloads and result[1] records unsuccessful downloads
          Integer[] result = new Integer[] { 0, 0 };
          if (dbResult.succeeded() && dbResult.result() != null && dbResult.result().size() > 0) {
            int pendingUsers = dbResult.result().size();
            log.debug("Successfully fetched the list of profiles were download_status was false");
            for (DownloadHandlerObject client : dbResult.result()) {
              processPendingRow(client, r -> {
                if (r.succeeded()) {
                  result[0] = result[0] + 1;
                  if (result[0] + result[1] == pendingUsers) {
                    resultHandler.handle(Future.succeededFuture(
                        "Successfully completed download handler. Downloaded the genome for " + result[0]
                            + " users. Unsuccessful in downloading the genome for " + result[1] + " users."));
                  }
                } else {
                  result[1] = result[1] + 1;
                  if (result[0] + result[1] == pendingUsers) {
                    resultHandler.handle(Future.succeededFuture(
                        "Successfully completed download handler. Downloaded the genome for " + result[0]
                            + " users. Unsuccessful in downloading the genome for " + result[1] + " users."));
                  }
                }
              });
            }

          } else if (dbResult.succeeded()) {
            log.debug("No profiles in the database to get genome data");
            resultHandler.handle(Future.succeededFuture("No profiles to download"));
          } else {
            log.error("Unable to  fetch the list of profiles were download_status was false.", dbResult.cause());
            resultHandler.handle(Future.failedFuture(
                "Unable to  fetch the list of profiles were download_status was false."));
          }
        });

  }

  public void processPendingRow(DownloadHandlerObject client, Handler<AsyncResult<String>> resultHandler) {

    //check if the client is genotyped and the times genomeData is called does not cross the limit
    if (client.getGenotyped() && client.getTimesGenomeDataCalled() < this.genomeDataLimit) {
      getGenomeDataForGenotypedClient(client, resultHandler);
    } else if (client.getGenotyped() && client.getTimesGenomeDataCalled() > this.genomeDataLimit) {
      //log error in database:- call to getGenome data exceeded the limit
      updateDownloadErrorInDatabase(555, "Calls to getGenomeData exceeded limit.Please "
              + "invoke 23andme api again  for the profile id.",
          client.getProfileId(), client.getUserId(), res1 -> {
            if (res1.failed()) {
              log.error("Error updating the download error in database", res1.cause());
            }
            resultHandler.handle(Future.failedFuture("Calls to getGenomeData exceeded limit."));
          });
    } else if (!client.getGenotyped() && client.getTimesGetGenotypedCalled() < this.genotypedLimit) {
      //else the client is not genotyped
      getGenomeDataForNotGenotypedClient(client, resultHandler);
    } else {
      //the client is not genotyped and we exceeded the limit to call getGenotyped
      log.error("Calls to getGenotyped exceeded limit for user id " + client.getUserId() + " and profile id "
          + client.getProfileId());
      //log error in database the calls to getGenotyped exceeded limit
      updateDownloadErrorInDatabase(555, "Calls to getGenotyped exceeded limit",
          client.getProfileId(), client.getUserId(), res1 -> {
            if (res1.failed()) {
              log.error("Error updating the download error in database", res1.cause());
            }
          });
      resultHandler.handle(Future.failedFuture("Calls to getGenotyped exceeded limit"));
    }

  }

  private void getGenomeDataForGenotypedClient(DownloadHandlerObject client,
                                               Handler<AsyncResult<String>> resultHandler) {

    Sql intervalQuery = getIntervalQueryForGenomeData(client.getTimesGenomeDataCalled());
    //check if it has been more than a day since we tried to download genome
    dbb.transactAsync(dbp -> {
          return dbp.get().toSelect(intervalQuery)
              .argString(client.getProfileId()).argString(client.getUserId())
              .argDateNowPerDb()
              .queryDateOrNull();
        },
        dbResult1 -> {
          if (dbResult1.succeeded()) {
            //check if it has been a day or more since last time the genome was retrieved
            //or it is first
            if (dbResult1.result() != null) {
              getGenomeData(client.getUserId(), client.getProfileId(),
                  client.getBearerToken(), res -> {
                    if (res.failed()) {
                      log.error(" Unable to download the genome data for profile_id " + client.getProfileId()
                          + " and user id " + client.userId);
                      resultHandler.handle(Future.failedFuture("failed to download genome data"));
                    }
                    if (res.succeeded()) {
                      resultHandler.handle(Future.succeededFuture());
                    }
                  });
            } else {
              // less than assigned time since getGenome was called
              log.debug("Tried downloading the genome  for profile id " + client.getProfileId()
                  + " and user id "
                  + client.getUserId()
                  + "in less than the assgined retry period. Will try again in sometime .");
              updatePendingErrorInDatabase(555,
                  "Genome data could not be downloaded in less than the assigned retry period. Will "
                      + "check again in sometime.",
                  client.getProfileId(), client.getUserId(), res2 -> {
                    if (res2.failed()) {
                      log.error("Error updating the pending error in database", res2.cause());
                    }
                    resultHandler.handle(Future.failedFuture("Less than assigned time since getGenome called"));
                  });

            }
          } else {
            log.error("Error running the interval query for getting genome data  profile id "
                + client.getProfileId() + " and user id " + client.getUserId(), dbResult1.cause());
            updatePendingErrorInDatabase(555, "Database error: " + getDatabaseExceptionMessage(dbResult1
                    .cause()),
                client.getProfileId(), client.getUserId(), res2 -> {
                  if (res2.failed()) {
                    log.error("Error updating the pending error in database", res2.cause());
                  }
                  resultHandler.handle(Future.failedFuture("Error running the interval query for getting genome data"));
                });
          }
        });

  }

  private void getGenomeDataForNotGenotypedClient(DownloadHandlerObject client,
                                                  Handler<AsyncResult<String>> resultHandler) {

    //check if it has been more than a day since we checked if the client was genotyped

    dbb.transactAsync(dbp -> {
          return dbp.get().toSelect(
              "select genotype_date from tm_user_info where profile_id = ? and user_id = ? and genotype_date + interval '24' hour <= ?")
              .argString(client.getProfileId()).argString(client.getUserId())
              .argDateNowPerDb()
              .queryDateOrNull();
        },
        dbResult1 -> {
          if (dbResult1.succeeded()) {
            //check if it has been a day or more since last time the refresh token was retrieved
            if (dbResult1.result() != null) {
              getNewRefreshToken(client.getProfileId(), client.getUserId(), r -> {
                if (r.succeeded()) {
                  //retrieve the genotype
                  getWhetherGenotyped(client.getUserId(), client.getBearerToken(),
                      client.getProfileId(), r1 -> {
                        if (r1.succeeded()) {
                          getGenomeData(client.getUserId(), client.getProfileId(), client
                              .getBearerToken(), r2 -> {
                            if (r2.failed()) {
                              log.debug("Unable to retrieve genome data for genotyped profile_id " + client
                                  .getProfileId() + " and user id " + client.getUserId());
                              resultHandler.handle(Future.failedFuture("Unable to retrieve genome data"));
                            }
                            if (r2.succeeded()) {
                              resultHandler.handle(Future.succeededFuture());
                            }
                          });
                        } else {
                          log.debug("The 23andme user api for profile id " + client.getProfileId() + " and user id "
                              + client.getUserId() + " returned error: " + r1.cause().getMessage());
                          resultHandler.handle(Future.failedFuture("23andme user api returned error"));
                        }
                      });
                } else {
                  log.debug("Failed to refresh token for profile id " + client.getProfileId() + " and user id "
                      + client.getUserId());
                  //resultHandler.handle(Future.failedFuture("Could not refresh the token."));
                  resultHandler.handle(Future.failedFuture("Failed to refresh token"));
                }

              });
            } else {
              // less than a day since genotype was last checked
              log.debug("The genotype for profile id " + client.getProfileId() + " and user id "
                  + client.getUserId() + " was checked, less than a day ago");
              updatePendingErrorInDatabase(555,
                  "The profile was not genotyped less than a day ago.Will "
                      + "check again in a day.",
                  client.getProfileId(), client.getUserId(), res2 -> {
                    if (res2.failed()) {
                      log.error("Error updating the pending error in database", res2.cause());
                    }
                  });
              resultHandler.handle(Future.failedFuture("Genotype was checked less than a day ago."));

            }

          } else {
            log.error("Error reteriving the days since last refresh token for  profile id" + client
                .getProfileId() + " and user id " + client.getUserId(), dbResult1.cause());
            updatePendingErrorInDatabase(555, "Database error: " + getDatabaseExceptionMessage(dbResult1
                    .cause()),
                client.getProfileId(), client.getUserId(), res2 -> {
                  if (res2.failed()) {
                    log.error("Error updating the pending error in database", res2.cause());
                  }
                });
            resultHandler.handle(Future.failedFuture("Error reteriving days since last refresh token"));
          }
        });

  }

  @NotNull
  public Handler<RoutingContext> twentyThreeAndMeHandler(Vertx vertx) {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String userId = request.getString("user");
      String profileId = request.getString("profile");
      String bToken = request.getString("token");
      String rToken = request.getString("refreshToken");

      if (userId == null || !userId.matches("[a-zA-Z0-9]{1,80}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end(new JsonObject().put("status", "failed")
                .put("message", "user is not valid").encode());
        log.error("User is not valid: " + userId);
        return;
      }

      if (profileId == null || !profileId.matches("[a-zA-Z0-9_]{1,80}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end(new JsonObject().put("status", "failed")
                .put("message", "profile is not valid").encode());
        log.error("Profile is not valid: " + profileId);
        return;
      }

      if (bToken == null || !bToken.matches("[a-zA-Z0-9]{1,4000}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end(new JsonObject().put("status", "failed")
                .put("message", "user token is not valid").encode());
        log.error("User token is not valid.");
        return;
      }

      if (rToken == null || !rToken.matches("[a-zA-Z0-9]{1,4000}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end(new JsonObject().put("status", "failed")
                .put("message", "refresh token is not valid").encode());
        log.error("Refresh token  is not valid.");
        return;
      }
      callTwentyThreeAndMe(userId, bToken, profileId, rToken, routingContext, resultHandler -> {
        String message = routingContext.response().getStatusMessage();
        routingContext.response().setStatusMessage("");
        routingContext.response().end(message);
      });

    };

  }

  @NotNull
  public Handler<RoutingContext> twentyThreeAndMeStatusHandler() {
    return routingContext -> {

      String statusKey = routingContext.request().getParam("statusKey");

      if (statusKey == null || !statusKey.matches("[a-zA-Z0-9]{1,100}")) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end(new JsonObject().put("status", "failed")
                .put("message", "status key is not valid").encode());
        log.error("Status key is not valid: " + statusKey);
        return;
      }

      findTheDownloadStatus(statusKey, routingContext, resultHandler -> {
        if (resultHandler.succeeded()) {
          String message = routingContext.response().getStatusMessage();
          routingContext.response().setStatusMessage("");
          routingContext.response().end(message);
        }
      });
    };
  }

  public <T> void findTheDownloadStatus(String statusKey, RoutingContext routingContext,
                                        Handler<AsyncResult<T>> resultHandler) {

    dbb.transactAsync(dbp -> {
          return dbp.get().toSelect("select download_status, download_error_code, download_error_msg, pending_error_code,"
              + "pending_error_msg from tm_user_info where status_key = ?").argString(
              statusKey)
              .<StatusHandlerObject>queryMany(
                  (r) -> {
                    StatusHandlerObject row = new StatusHandlerObject();
                    row.setDownloadStatus(r.getBooleanOrNull("download_status"));
                    row.setDownloadErrorCode(r.getIntegerOrZero("download_error_code"));
                    row.setDownloadErrorMsg(r.getStringOrNull("download_error_msg"));
                    row.setPendingErrorCode(r.getIntegerOrZero("pending_error_code"));
                    row.setPendingErrorMsg(r.getStringOrNull("pending_error_msg"));

                    return row;
                  });

        },
        result -> {
          if (result.succeeded() && result.result().size() > 0) {
            Iterator<StatusHandlerObject> iterator = result.result().iterator();
            StatusHandlerObject statusObj = iterator.next();

            if (statusObj.getDownloadStatus()) {
              routingContext.response().setStatusCode(200);
              routingContext.response().setStatusMessage(new JsonObject().put("status", "complete").encode());
              log.debug("Status returned: complete");
              resultHandler.handle(Future.succeededFuture());
              return;

            } else if (statusObj.getDownloadErrorCode() == 555) {
              //These were mhealth server internal errors
              routingContext.response().setStatusCode(500);
              routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                  .put("message", statusObj.getDownloadErrorMsg()).encode());
              log.debug("Status returned failed. Message: " + statusObj.getDownloadErrorMsg());
              resultHandler.handle(Future.succeededFuture());
              return;
            } else if (statusObj.getDownloadErrorCode() != 0 && statusObj.getDownloadErrorCode() != 555) {
              routingContext.response().setStatusCode(200);
              routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                  .put("errorCode", statusObj.getDownloadErrorCode())
                  .put("message", statusObj.getDownloadErrorMsg()).encode());
              log.debug("Status returned failed. ErrorCode: " + statusObj.getDownloadErrorCode() + " Message: "
                  + statusObj.getDownloadErrorMsg());
              resultHandler.handle(Future.succeededFuture());
              return;
            } else if (statusObj.getPendingErrorCode() != 0) {
              routingContext.response().setStatusCode(200);
              routingContext.response().setStatusMessage(new JsonObject()
                  .put("status", "pending").encode());
              log.debug("Status returned pending");
              resultHandler.handle(Future.succeededFuture());
              return;
            } else if (!statusObj.getDownloadStatus() && statusObj.getDownloadErrorCode() == 0 && statusObj
                .getPendingErrorCode() == 0) { //Error should not have happened
              routingContext.response().setStatusCode(200);
              routingContext.response().setStatusMessage(new JsonObject()
                  .put("status", "pending").encode());
              //this is a very possible situation when the row is inserted but no gneome has yet been downloaded and no error has occured 
              // and the status api has been called.So we are truly in a pending state
              log.debug("Status returned pending. Though no error recorderd.");
              resultHandler.handle(Future.succeededFuture());
              return;
            }

          } else if (result.result() == null || result.result().isEmpty()) {
            //this indicates that the statusKey was not found in the database, hence it is invalid key
            log.error("No status key found in database " + statusKey);
            routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code());
            routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                .put("message", "invalid status key").encode());
            log.debug("Status returned, invalid status key");
            resultHandler.handle(Future.succeededFuture());
          } else if (result.failed()) {
            log.error("Database Error in retriving the download status information", result.cause());
            routingContext.response().setStatusCode(500);
            routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                .put("message", "Database error: " + getDatabaseExceptionMessage(result.cause())).encode());
            log.debug("Status returned failed. Message: " + "Database error: " + getDatabaseExceptionMessage(result
                .cause()));
            resultHandler.handle(Future.succeededFuture());
          }

        });

  }

  @NotNull
  private <T> void getWhetherGenotyped(String userId, String bToken,
                                       String profId, Handler<AsyncResult<T>> resultHandler) {

    //increment the times_genome_data__called field in database
    increment_times_get_genotyped_called(userId, profId, incrementResult -> {
      if (incrementResult.succeeded()) {
        twentyThreeAndMe.userInfo(bToken, result -> {
          if (result.succeeded()) {
            UserResult userInfo = result.result();
            Profile prof = userInfo.profiles.get(0);
            Boolean genotyped = prof.genotyped;
            // update the genotyped field for the profile_id
            dbb.transactAsync(dbp -> {
              dbp.get().toUpdate(
                  "update tm_user_info set genotyped = ? , genotype_date = ? where profile_id = ? and user_id = ?")
                  .argBoolean(genotyped).argDateNowPerDb()
                  .argString(profId).argString(userId).update(1);
              return null;
            }, dbResult -> {
              if (dbResult.succeeded() && genotyped) {
                log.debug("The profile with profile id " + profId + "and user id " + userId
                    + "has been genotyoed");
                resultHandler.handle(Future.succeededFuture());
              } else if (dbResult.succeeded() && !genotyped) {
                log.debug("The profile with  profile id "
                    + profId + " and userId " + userId + " is not genotyoed");
                updatePendingErrorInDatabase(555,
                    "The profile is not genotyped", profId, userId, res2 -> {
                      if (res2.failed()) {
                        log.error("Error updating the pending error in database", res2.cause());
                      }
                    });
                resultHandler.handle(Future.failedFuture("The profile with  profile id "
                    + profId + " and userId" + userId + " is not genotyoed"));
              } else {
                log.error(" Database error in updating the genotyped field for profile id "
                    + profId + " and userId " + userId, dbResult.cause());
                updatePendingErrorInDatabase(555,
                    "Database error: " + getDatabaseExceptionMessage(dbResult.cause()),
                    profId, userId, res2 -> {
                      if (res2.failed()) {
                        log.error("Error updating the pending error in database", res2.cause());
                      }
                    });
                resultHandler.handle(Future.failedFuture("Database error in updating the genotyped field."));
              }

            });

          } else {
            //the user api call failed
            JsonObject failure = new JsonObject(result.cause().getMessage());
            if (failure.getInteger("statusCode") == 401) {
              //Unauthorized. May be the bearer token expired so try to refresh token again and then 
              // continue with this operation
              dbb.transactAsync(dbp -> {
                    return dbp.get().toSelect(
                        "select token_refresh_date from tm_user_info where profile_id = ? and user_id = ? and token_refresh_date + interval '24' hour <= ?")
                        .argString(profId).argString(userId).argDateNowPerDb().queryDateOrNull();
                  },
                  dbResult -> {
                    if (dbResult.succeeded()) {
                      //check if it has been a day or more since last time the refresh token was retrieved
                      if (dbResult.result() != null) {
                        getNewRefreshToken(profId, userId, r1 -> {
                          if (r1.succeeded()) {
                            getWhetherGenotyped(userId, bToken,
                                profId, r2 -> {
                                  if (r2.failed()) {
                                    resultHandler.handle(Future.failedFuture("Fail to get genotyped."));
                                  } else {
                                    resultHandler.handle(Future.succeededFuture());
                                  }
                                });
                            //future.complete();
                          } else {
                            resultHandler.handle(Future.failedFuture("Could not refresh the token."));
                          }

                        });
                      } else {
                        log.debug("Token refreshed less than a day ago for profile id " + profId + " and user id "
                            + userId);
                        //update the database error message to say that token refreshed less than a day ago
                        updatePendingErrorInDatabase(555, "Token refreshed less than a day ago",
                            profId, userId, res1 -> {
                              if (res1.failed()) {
                                log.error("Error updating the download error in database", res1.cause());
                              }
                            });

                        resultHandler.handle(Future.failedFuture("Token refreshed less than a day ago"));
                      }
                    }

                  });

            } else if (failure.getInteger("statusCode") == 404) {
              //An internal server error.We mark it as pending error
              updatePendingErrorInDatabase(failure.getInteger("statusCode"),
                  "23andMe user api returned error.Error:  " + failure.getValue("message").toString(),
                  profId, userId, res2 -> {
                    if (res2.failed()) {
                      log.error("Error updating the pending error in database", res2.cause());
                    }
                  });
              // there is error log it
              log.debug("The 23andme user api for profile " + profId + " and user id " + userId
                  + "retruned an error: " + failure.getValue("message").toString());
              resultHandler.handle(Future.failedFuture("The 23andme user api for profile " + profId + " and user id "
                  + userId
                  + "retruned an error: " + failure.getValue("message").toString()));
            } else {
              //Any other error is download error
              updateDownloadErrorInDatabase(failure.getInteger("statusCode"),
                  "23andMe user api returned error.Error:  " + failure.getValue("message").toString(),
                  profId, userId, res1 -> {
                    if (res1.failed()) {
                      log.error("Error updating the download error in database", res1.cause());
                    }
                  });
              // there is error log it
              log.error("The 23andme user api for profile " + profId + " and user id " + userId
                  + "retruned an error: " + failure.getValue("message").toString());
              resultHandler.handle(Future.failedFuture("The 23andme user api for profile " + profId + " and user id "
                  + userId
                  + "retruned an error: " + failure.getValue("message").toString()));
            }
          }
        });
      } else {
        resultHandler.handle(Future.failedFuture(
            "Exception while incrementing the times get_genotyped called for profileId " + profId
                + "and user id " + userId));
      }
    });

  }

  @NotNull
  public <T> void getGenomeData(String userId, String profileId,
                                String bToken, Handler<AsyncResult<T>> resultHandler) {

    //increment the times_genome_data__called field in database
    increment_times_genome_data_called(userId, profileId, incrementResult -> {
      if (incrementResult.succeeded()) {
        twentyThreeAndMe.geneticData(profileId, bToken, result -> {
          if (result.succeeded()) {
            //store the genome data in database and make the download status true

            dbb.transactAsync(dbp -> {
              dbp.get().toUpdate(
                  "update tm_user_info set  download_status = ?, genome_date = ? where profile_id = ? and user_id =?")
                  .argBoolean(true).argDateNowPerDb().argString(
                  profileId).argString(userId)
                  .update(1);
              dbp.get().toUpdate(
                  "update tm_download set genetic_data = :secret_gd where profile_id = ? and user_id =?")
                  .argClobString("secret_gd", result.result().genome).argString(profileId).argString(userId)
                  .update(1);
              return null;
            }, dbResult -> {
              if (dbResult.succeeded()) {
                log.debug("Successfully stored the genomedata for profile id " + profileId
                    + "and user id " + userId);
                resultHandler.handle(Future.succeededFuture());
              } else {
                log.error("Error storing the genome data for profile id " + profileId
                    + " and user id " + userId, dbResult.cause());
                updatePendingErrorInDatabase(555, "Database error: " + getDatabaseExceptionMessage(dbResult.cause()),
                    profileId, userId, res2 -> {
                      if (res2.failed()) {
                        log.error("Error updating the pending error in database", res2.cause());
                      }
                    });
                resultHandler.handle(Future.failedFuture("database error storing genome data"));
              }
            });
          } else {
            //23andme api call returned error
            JsonObject failure = new JsonObject(result.cause().getMessage());
            if (failure.getInteger("statusCode") == 401) {
              //the token has expired.//Unauthorized token
              //Check the token refresh date and the # of times the token is refreshed
              //other possible errors {"error_description": "Access token has insufficient scope: genomes", "error": "insufficient_scope"}

              dbb.transactAsync(dbp -> {
                    return dbp.get().toSelect(
                        "select token_refresh_date from tm_user_info where profile_id = ? and user_id = ? and token_refresh_date + interval '24' hour <= ?")
                        .argString(profileId).argString(userId).argDateNowPerDb().queryDateOrNull();
                  },
                  dbResult -> {
                    if (dbResult.succeeded()) {
                      //check if it has been a day or more since last time the refresh token was retrieved
                      if (dbResult.result() != null) {
                        //retrieve new token
                        getNewRefreshToken(profileId, userId, r1 -> {
                          if (r1.succeeded()) {
                            getGenomeData(userId, profileId, bToken, r2 -> {
                              if (r2.succeeded()) {
                                resultHandler.handle(Future.succeededFuture());
                              } else {
                                resultHandler.handle(Future.failedFuture("Failed to get genome data"));
                              }
                            });
                          } else {
                            resultHandler.handle(Future.failedFuture("Failed to refresh the token"));
                          }
                        });

                      } else {
                        log.debug("Token refreshed less than a day ago for profile id " + profileId + " and user id "
                            + userId);
                        //update the database error message to say that token refreshed less than a day ago
                        updatePendingErrorInDatabase(555, "Token refreshed less than a day ago",
                            profileId, userId, res1 -> {
                              if (res1.failed()) {
                                log.error("Error updating the download error in database", res1.cause());
                              }
                            });
                        resultHandler.handle(Future.failedFuture("Token refreshed less than a day ago"));
                      }

                    } else {
                      log.debug("Error reteriving the days since last refresh token for  profile id "
                          + profileId + "and user id " + userId, dbResult);
                      updatePendingErrorInDatabase(555,
                          "Database error: " + getDatabaseExceptionMessage(dbResult.cause()),
                          profileId, userId, res2 -> {
                            if (res2.failed()) {
                              log.error("Error updating the pending error in database", res2.cause());
                            }
                          });
                      resultHandler.handle(Future.failedFuture("Database error while retriving days since last refresh"));
                    }
                  });
            } else if (failure.getInteger("statusCode") == 404) {
              log.debug("Error storing the genomedata for profile id " + profileId
                  + ". Error: " + failure.getValue("message")
                  .toString());
              //update the database download_error column
              updatePendingErrorInDatabase(failure.getInteger("statusCode"), "Error storing genome data.Cause: "
                      + failure.getValue("message")
                      .toString(),
                  profileId, userId,
                  res1 -> {
                    if (res1.failed()) {
                      log.error("Error updating the download error in database", res1.cause());
                    }
                  });
              resultHandler.handle(Future.failedFuture("Token has insufficient scope"));
            } else {
              log.error("Error storing the genomedata for profile id " + profileId + ".Error status code is "
                  + failure.getInteger("statusCode") + " Error message: " + failure.getValue("message").toString());
              //upload the pending error column
              updateDownloadErrorInDatabase(failure.getInteger("statusCode"), "Error storing genome data.Cause: "
                      + failure.getValue("message")
                      .toString(),
                  profileId, userId,
                  res2 -> {
                    if (res2.failed()) {
                      log.error("Error updating the pending error in database", res2.cause());
                    }
                  });
              resultHandler.handle(Future.failedFuture("Error storing the genome data"));
            }

          }

        });

      } else {
        resultHandler.handle(Future.failedFuture(
            "Exception while incrementing the times get_genome_data called for profileId " + profileId
                + "and user id" + userId));
      }
    });

  }

  @NotNull
  private <T> void getNewRefreshToken(String profileId, String userId,
                                      Handler<AsyncResult<RefreshResult>> resultHandler) {
    //get the refresh_token from the database
    dbb.transactAsync(dbp -> {
      return dbp.get().toSelect(
          "select refresh_token from tm_user_info where profile_id = ? and user_id = ?")
          .argString(profileId).argString(userId).queryStringOrNull();
    }, dbResult -> {
      if (dbResult.succeeded()) {
        twentyThreeAndMe.refreshToken(dbResult.result(), result -> {
          if (result.succeeded()) {
            //update the refresh token in database 
            dbb.transactAsync(dbp -> {
              dbp.get().toUpdate(
                  "update tm_user_info set refresh_token = :secret_rt,token_refresh_date = ? where profile_id = ? and user_id =?")
                  .argString("secret_rt", result.result().refreshToken).argDateNowPerDb()
                  .argString(profileId).argString(userId).update(1);
              return null;
            }, dbResult1 -> {
              if (dbResult1.succeeded()) {
                resultHandler.handle(Future.succeededFuture(result.result()));
              } else {
                resultHandler.handle(Future.failedFuture("Database exception while updating refresh_token"));
              }
            });

          } else {
            //23andme api call returned error
            JsonObject failure = new JsonObject(result.cause().getMessage());
            if (failure.getInteger("statusCode") == 404) {
              //for all these codes we want to report the error back to user.So we set the download_erro_code and message
              updatePendingErrorInDatabase(failure.getInteger("statusCode"), "Unable to refresh token.Cause: "
                      + failure.getValue("message")
                      .toString(),
                  profileId, userId,
                  res1 -> {
                    if (res1.failed()) {
                      log.error("Error updating the pending error in database", res1.cause());
                    }
                  });
              log.debug("The get refresh token api returned status code " + failure.getInteger("statusCode")
                  + " .The message was " + failure.getValue("message").toString() + " for profile id " + profileId
                  + " and user id "
                  + userId);
              resultHandler.handle(Future.failedFuture("Fialed to refresh token"));
            } else {
              //for any other status code we log it as pending error
              updateDownloadErrorInDatabase(failure.getInteger("statusCode"), "Unable to refresh token.Cause: "
                      + failure
                      .getValue("message")
                      .toString(),
                  profileId, userId,
                  res2 -> {
                    if (res2.failed()) {
                      log.error("Error updating the download error in database", res2.cause());
                    }
                  });
              log.error("The get refresh token api returned status code " + failure.getInteger("statusCode")
                  + " .The message was " + failure.getValue("message").toString() + " for profile id " + profileId
                  + " and user id "
                  + userId);

              resultHandler.handle(Future.failedFuture("Fialed to refresh token"));
            }
          }
        });

      } else {
        log.debug("Unable to get refresh token from database for profile id " + profileId + "and user id " + userId,
            dbResult.cause());
        updatePendingErrorInDatabase(555, "Database error:  " + getDatabaseExceptionMessage(dbResult.cause()),
            profileId, userId,
            res2 -> {
              if (res2.failed()) {
                log.error("Error updating the pending error in database", res2.cause());
              }
            });
        resultHandler.handle(Future.failedFuture("Exception in retrieving refresh token from database"));
      }
    });

  }

  @NotNull
  private <T> void increment_times_genome_data_called(String userId, String profileId,
                                                      Handler<AsyncResult<T>> resultHandler) {

    dbb.transactAsync(dbp -> {
      dbp.get().toUpdate(
          "update tm_user_info set times_genome_data_called =  times_genome_data_called + 1, genome_date = ?  where profile_id = ? and user_id = ?")
          .argDateNowPerDb().argString(profileId).argString(userId).update(1);
      return null;
    }, dbResult -> {
      if (dbResult.succeeded()) {
        log.debug("Database successfully incremented the times_genome_data_called for profile_id "
            + profileId + "and user id " + userId);
        resultHandler.handle(Future.succeededFuture());
      } else {
        log.debug("Database error while incrementing the times_genome_data_called for profile_id "
            + profileId + "and user id " + userId, dbResult.cause());
        updatePendingErrorInDatabase(555,
            "Database error:  " + getDatabaseExceptionMessage(dbResult.cause()),
            profileId, userId, res2 -> {
              if (res2.failed()) {
                log.error("Error updating the pending error in database", res2.cause());
              }
            });
        resultHandler.handle(Future.failedFuture("Database update failed"));
      }
    });

  }

  @NotNull
  private <T> void increment_times_get_genotyped_called(String userId, String profileId,
                                                        Handler<AsyncResult<T>> resultHandler) {

    dbb.transactAsync(dbp -> {
      dbp.get().toUpdate(
          "update tm_user_info set times_get_genotyped_called =  times_get_genotyped_called + 1  where profile_id = ? and user_id = ?")
          .argString(profileId).argString(userId).update(1);
      return null;
    }, dbResult -> {
      if (dbResult.succeeded()) {
        log.debug("Database successfully incremented the times_genotyped_called for profile_id "
            + profileId + "and user id " + userId);
        resultHandler.handle(Future.succeededFuture());
      } else {
        log.debug("Database error while incrementing the times_genotyped_called for profile_id "
            + profileId + "and user id " + userId, dbResult.cause());
        updatePendingErrorInDatabase(555,
            "Database error: " + getDatabaseExceptionMessage(dbResult.cause()),
            profileId, userId, res2 -> {
              if (res2.failed()) {
                log.error("Error updating the pending error in database", res2.cause());
              }

            });
        resultHandler.handle(Future.failedFuture("Database update failed"));
      }
    });

  }

  @NotNull
  private <T> void updateDownloadErrorInDatabase(Integer errCode, String errMsg, String profileId,
                                                 String userId, Handler<AsyncResult<T>> resultHandler) {
    //log error in database:- call to getGenome data exceeded the limit

    dbb.transactAsync(dbp -> {
      dbp.get().toUpdate(
          "update tm_user_info set download_error_code = ?, download_error_msg = ? where"
              + " profile_id = ? and user_id = ?").argInteger(errCode).argString(errMsg)
          .argString(profileId).argString(userId).update(1);
      return null;
    }, dbResult -> {
      if (dbResult.succeeded()) {
        log.debug("Successfully updated the download_error_code for profile id "
            + profileId + " and user id " + userId);
        resultHandler.handle(Future.succeededFuture());
      } else {
        log.error("Unable to update the download_error_code for profile_id " + profileId
            + " and user id " + userId, dbResult);
        resultHandler.handle(Future.failedFuture("Download error code not updated"));
      }
    });

  }

  private <T> void updatePendingErrorInDatabase(Integer errCode, String errMsg, String profileId,
                                                String userId, Handler<AsyncResult<T>> resultHandler) {
    //log error in database:- call to getGenome data exceeded the limit
    dbb.transactAsync(dbp -> {
      dbp.get().toUpdate(
          "update tm_user_info set pending_error_code = ?, pending_error_msg = ? where"
              + " profile_id = ? and user_id = ?").argInteger(errCode).argString(errMsg)
          .argString(profileId).argString(userId).update(1);
      return null;
    }, dbResult -> {

      if (dbResult.succeeded()) {
        log.debug("Successfully updated the pending_error_code for profile id "
            + profileId + " and user id " + userId);
        resultHandler.handle(Future.succeededFuture());
      } else {
        log.error("Unable to update the pending_error_code for profile_id " + profileId
            + " and user id " + userId, dbResult);
        resultHandler.handle(Future.failedFuture("Pending error code not updated"));
      }
    });

  }

  public <T> void callTwentyThreeAndMe(String userId, String bToken, String profileId, String rToken,
                                       RoutingContext routingContext, Handler<AsyncResult<T>> resultHandler) {
    String statusKey = new SessionKeyGenerator(secureRandom).create();
    //Get the profile id for the user from 23AndMe
    twentyThreeAndMe.userInfo(bToken, result -> {
      if (result.succeeded()) {
        UserResult userInfo = result.result();
        Profile prof = userInfo.profiles.get(0);
        String tmProfId = prof.id;
        Boolean genotyped = prof.genotyped;
        //Check if the user id retrieved is the same as the one provided by lifeMap
        if (!userInfo.id.equals(userId)) {
          log.error("UserId provided does not match the userId retrieved  from 23AndMe for the given userToken");
          routingContext.response().setStatusCode(500);
          routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
              .put("message", "userId does not match the userId retrieved  from 23AndMe").encode());
          resultHandler.handle(Future.failedFuture("UserId did not match what was provided by LifeMap"));
          return;
        }

        //Check if the profile id retrieved is the same as the one provided by lifeMap
        if (!tmProfId.equals(profileId)) {
          log.error("ProfileId provided does not match the profileId retrieved  from 23AndMe for the given userToken");
          routingContext.response().setStatusCode(500);
          routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
              .put("message", "profileId does not match the profileId retrieved  from 23AndMe").encode());
          resultHandler.handle(Future.failedFuture("ProfileId does not match what was provided by LifeMap"));
          return;
        }

        //store the profile id in the database. First check that the profile id does not
        //already exists.If so reset the counters.
        dbb.transactAsync(dbp -> {
          return dbp.get().toSelect(
              "select download_status from tm_user_info where profile_id = ? and user_id = ?")
              .argString(profileId).argString(userId).queryBooleanOrNull();
        }, dbResult -> {
          if (dbResult.succeeded() && dbResult.result() != null) {

            //profileId already exists so just update the existing row
            if (!dbResult.result()) {
              dbb.transactAsync(dbp -> {
                dbp.get().toUpdate(
                    "update tm_user_info set bearer_token = :secret_bt, refresh_token = :secret_rt,genotyped = ?,genotype_date = ?,"
                        + "token_refresh_date = ?,download_error_code = ?, download_error_msg = ?, pending_error_code = ?,"
                        + "pending_error_msg = ?,status_key = ?,times_genome_data_called = ?,"
                        + "times_get_genotyped_called = ?, create_date = ? where profile_id = ? and user_id = ?")
                    .argString("secret_bt",
                        bToken)
                    .argString("secret_rt", rToken)
                    .argBoolean(genotyped).argDateNowPerDb().argDateNowPerDb().argInteger(0).argString(null)
                    .argInteger(0).argString(null).argString(statusKey).argInteger(0).argInteger(0).argDateNowPerDb()
                    .argString(profileId)
                    .argString(userId).update(1);
                return null;
              }, dbResult1 -> {
                if (dbResult1.failed()) {
                  log.error("Error while updating the database for user id " + userId
                      + " and profileId " + profileId, dbResult1.cause());
                  routingContext.response().setStatusCode(500);
                  routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                      .put("message", "Database error:  " + getDatabaseExceptionMessage(dbResult1.cause())).encode());
                  resultHandler.handle(Future.failedFuture("database error"));
                } else {
                  log.debug("Successfully updated the database for user id " + userId
                      + " and profileId " + profileId);
                  routingContext.response().setStatusCode(200);
                  routingContext.response().setStatusMessage(new JsonObject().put("status", "pending")
                      .put("statusKey", statusKey).encode());
                  //Try to get the genome data if already genotyped
                  if (genotyped) {
                    getGenomeData(userId, profileId, bToken, res -> {
                    });
                  }
                  //whether we succeed to get genoome data or not we report success                 
                  resultHandler.handle(Future.succeededFuture());
                }
              });

            } else if (dbResult.result()) {
              // the genome data is already downloaded for this profile id
              log.debug("The genome data is already downloaded for user id  " + userId
                  + " and profileId"
                  + profileId);
              routingContext.response().setStatusCode(200);
              routingContext.response().setStatusMessage(new JsonObject().put("status", "complete").encode());
              resultHandler.handle(Future.succeededFuture());
            }
          } else if (dbResult.succeeded() && dbResult.result() == null) {
            //profileId does not exist insert a new row
            dbb.transactAsync(dbp -> {
              dbp.get().toInsert("insert into tm_user_info (user_id, bearer_token, refresh_token,"
                  + "download_status,status_key,profile_id,genotyped,genotype_date,token_refresh_date,times_genome_data_called,"
                  + "times_get_genotyped_called, download_error_code,download_error_msg,pending_error_code,pending_error_msg,create_date) values (?,:secret_bt,:secret_rt,?,?,?,?,?,?,?,?,?,?,?,?,?)")
                  .argString(userId).argString("secret_bt", bToken).argString("secret_rt", rToken).argBoolean(false)
                  .argString(statusKey)
                  .argString(profileId).argBoolean(genotyped).argDateNowPerDb().argDateNowPerDb().argInteger(0)
                  .argInteger(0).argInteger(0).argString(null).argInteger(0).argString(null).argDateNowPerDb().insert(
                  1);
              dbp.get().toInsert("insert into tm_download (user_id,profile_id)values (?,?)").argString(userId)
                  .argString(profileId).insert(1);
              return null;
            }, dbResult2 -> {
              if (dbResult2.succeeded()) {
                log.debug("Successfully inserted the row for user id " + userId
                    + " and profileId " + profileId + " in the database");
                routingContext.response().setStatusCode(200);
                routingContext.response().setStatusMessage(new JsonObject().put("status", "pending")
                    .put("statusKey", statusKey).encode());
                //Try to get the genome data if already genotyped
                if (genotyped) {
                  getGenomeData(userId, profileId, bToken, res -> {
                  });
                }
                resultHandler.handle(Future.succeededFuture());

              } else {
                log.error("Unable to store the row for user id " + userId + " and profile id "
                    + profileId + " in the database.", dbResult2.cause());
                routingContext.response().setStatusCode(500);
                routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                    .put("message", "Database error: " + getDatabaseExceptionMessage(dbResult2.cause()))
                    .encode());
                resultHandler.handle(Future.failedFuture("database error"));
              }
            });
          } else {
            log.error(" Unable to get profile id from the database.", dbResult.cause());
            routingContext.response().setStatusCode(500);
            routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
                .put("message", "Database error: " + getDatabaseExceptionMessage(dbResult.cause())).encode());
            resultHandler.handle(Future.failedFuture("database error"));
          }

        });
      } else {
        // If the call to user api does not succeed we report it back to LifeMap
        JsonObject failure = new JsonObject(result.cause().getMessage());
        log.error("Error trying to call user end point on 23andme for userId " + userId
            + " and profileId " + profileId
            + " The error code: " + failure.getInteger("statusCode") + ".Error Message: "
            + failure.getValue("message").toString());
        routingContext.response().setStatusCode(200);
        routingContext.response().setStatusMessage(new JsonObject().put("status", "failed")
            .put("errorCode", failure.getInteger("statusCode"))
            .put("message", failure.getValue("message").toString()).encode());
        resultHandler.handle(Future.failedFuture("Error calling 23andme user api"));

      }

    });

  }

  public Sql getIntervalQueryForGenomeData(int timesGenomeDataCalled) {
    Sql intervalQuery =
        new Sql(
            "select genome_date from tm_user_info where profile_id = ? and user_id = ?  and genome_date + interval '1' hour <= ?");
    if (timesGenomeDataCalled == 2) {
      intervalQuery =
          new Sql(
              "select genome_date from tm_user_info where profile_id = ? and user_id = ?  and genome_date + interval '4' hour <= ?");
    } else if (timesGenomeDataCalled == 3) {
      intervalQuery =
          new Sql(
              "select genome_date from tm_user_info where profile_id = ? and user_id = ?  and genome_date + interval '8' hour <= ?");
    } else if (timesGenomeDataCalled >= 4) {
      intervalQuery =
          new Sql(
              "select genome_date from tm_user_info where profile_id = ? and user_id = ?  and genome_date + interval '16' hour <= ?");
    }
    return intervalQuery;
  }

  public String getDatabaseExceptionMessage(Throwable exception) {
    String message = new String();
    if (exception.toString().indexOf("errorCode=") >= 0) {
      message = exception.toString().substring(exception.toString().indexOf("errorCode="),
          exception.toString().indexOf(
              ")"));
    } else {
      message = exception.getMessage();
    }
    return message;
  }

  public class DownloadHandlerObject {

    private String profileId;
    private String userId;
    private String bearerToken;
    private Boolean genotyped;
    private String refreshToken;
    private Integer timesGenomeDataCalled;
    private Integer timesGetGenotypedCalled;

    public String getProfileId() {
      return profileId;
    }

    public void setProfileId(String profileId) {
      this.profileId = profileId;
    }

    public String getUserId() {
      return userId;
    }

    public void setUserId(String userId) {
      this.userId = userId;
    }

    public String getBearerToken() {
      return bearerToken;
    }

    public void setBearerToken(String bearerToken) {
      this.bearerToken = bearerToken;
    }

    public Boolean getGenotyped() {
      return genotyped;
    }

    public void setGenotyped(Boolean genotyped) {
      this.genotyped = genotyped;
    }

    public String getrefreshToken() {
      return refreshToken;
    }

    public void setrefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
    }

    public Integer getTimesGenomeDataCalled() {
      return timesGenomeDataCalled;
    }

    public void setTimesGenomeDataCalled(Integer timesGenomeDataCalled) {
      this.timesGenomeDataCalled = timesGenomeDataCalled;
    }

    public Integer getTimesGetGenotypedCalled() {
      return timesGetGenotypedCalled;
    }

    public void setTimesGetGenotypedCalled(Integer timesGetGenotypedCalled) {
      this.timesGetGenotypedCalled = timesGetGenotypedCalled;
    }

  }

  public class StatusHandlerObject {

    private Boolean downloadStatus;
    private Integer downloadErrorCode;
    private String downloadErrorMsg;
    private Integer pendingErrorCode;
    private String pendingErrorMsg;

    public Boolean getDownloadStatus() {
      return downloadStatus;
    }

    public void setDownloadStatus(Boolean downloadStatus) {
      this.downloadStatus = downloadStatus;
    }

    public Integer getDownloadErrorCode() {
      return downloadErrorCode;
    }

    public void setDownloadErrorCode(Integer downloadErrorCode) {
      this.downloadErrorCode = downloadErrorCode;
    }

    public String getDownloadErrorMsg() {
      return downloadErrorMsg;
    }

    public void setDownloadErrorMsg(String downloadErrorMsg) {
      this.downloadErrorMsg = downloadErrorMsg;
    }

    public Integer getPendingErrorCode() {
      return pendingErrorCode;
    }

    public void setPendingErrorCode(Integer pendingErrorCode) {
      this.pendingErrorCode = pendingErrorCode;
    }

    public String getPendingErrorMsg() {
      return pendingErrorMsg;
    }

    public void setPendingErrorMsg(String pendingErrorMsg) {
      this.pendingErrorMsg = pendingErrorMsg;
    }

  }

}
