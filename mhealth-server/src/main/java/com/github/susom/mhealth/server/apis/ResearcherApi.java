package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.Metric;
import com.github.susom.database.Sql;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.BadRequestException;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.mhealth.server.container.ResearchAuthHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jetbrains.annotations.NotNull;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class provides api's for research community to download the mhealth data
 */
public class ResearcherApi {
  private static final Logger log = LoggerFactory.getLogger(ResearcherApi.class);
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final Config config;
  private final String portalApiHost;
  private final Integer portalApiPort;
  private final String portalApiContext;
  private boolean encryptionEnabled;
  private final Map<String, RecipientInfo> recipientsByVersion = new HashMap<>();
  private final Map<RecipientId, RecipientInfo> recipientsById = new HashMap<>();

  public ResearcherApi(Builder dbb, SecureRandom secureRandom, Config config) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.config = config;
    portalApiHost = config.getString("portal.api.host", "localhost");
    portalApiPort = config.getInteger("portal.api.port", 8002);
    portalApiContext = "/" + config.getString("portal.api.context", "server");

    try {
      Security.addProvider(new BouncyCastleProvider());
      StringBuilder message = new StringBuilder("Using the following keys for decryption (param 0 indicates default):");

      for (int i = 0; ; i++) {
        String publicKeyFile;
        String privateKeyFile;
        String privKeyPassw;
        if (i == 0) {
          publicKeyFile = config.getString("publicKeyFile", "pubkey.pem");
          privateKeyFile = config.getString("privateKeyFile", "privkey.pem");
          privKeyPassw = config.getString("privateKeyPassword", "garrick");
        } else {
          publicKeyFile = config.getString("publicKeyFile." + i);
          if (publicKeyFile == null) {
            break;
          }
          privateKeyFile = config.getString("privateKeyFile." + i);
          privKeyPassw = config.getString("privateKeyPassword." + i);
          if (privateKeyFile == null || privKeyPassw == null) {
            log.warn("Ignoring config 'publicKeyFile.{}' because corresponding 'privateKeyFile.{}' "
                + "or 'privateKeyPassword.{}' was not set", i, i, i);
            continue;
          }
        }

        // Read the public key
        PemObject publicKey = new PemReader(new StringReader(FileUtils.readFileToString(new File(publicKeyFile), "utf-8"))).readPemObject();
        X509CertificateHolder certHolder = new X509CertificateHolder(publicKey.getContent());
        RecipientId recipientId = new KeyTransRecipientId(certHolder.getIssuer(), certHolder.getSerialNumber());

        // Read the private key
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(privKeyPassw.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair privateKeyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
        Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKeyPair.getPrivate());
        recipientsByVersion.put(Integer.toString(i), new RecipientInfo(recipientId, recipient));
        recipientsById.put(recipientId, new RecipientInfo(recipientId, recipient));
        message.append("\n  param=").append(i).append(" public=").append(publicKeyFile)
            .append(" private=").append(privateKeyFile);
      }
      log.debug(message.toString());
      encryptionEnabled = true;
    } catch (Exception e) {
      log.error("Unable to read public/private key pair - decrypting of files will be disabled", e);
    }
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    MetricsHandler metricsHandler =
        new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests"));
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);
    ResearchAuthHandler authenticationHandler = new ResearchAuthHandler(dbb);

    router.post("/api/v1/token").handler(metricsHandler);
    // Issue a token to the study site so it knows the authenticated user
    // and may be able to do things for them
    router.post("/api/v1/token").handler(rc -> {
      // Make the HTML form encoded body accessible to getFormAttribute()
      rc.request().setExpectMultipart(true);
      rc.next();
    });
    router.post("/api/v1/token").handler(smallBodyHandler);
    router.post("/api/v1/token").handler(refreshTokenHandler(vertx)).failureHandler(this::fail);

    router.get("/api/v1/participants").handler(authenticationHandler);
    router.get("/api/v1/participants").handler(metricsHandler);
    // router.get("/api/v1/participants").handler(smallBodyHandler);
    router.get("/api/v1/participants").handler(participantsHandler(vertx));

    router.get("/api/v1/files").handler(authenticationHandler);
    router.get("/api/v1/files").handler(metricsHandler);
    // router.get("/api/v1/files").handler(smallBodyHandler);
    router.get("/api/v1/files").handler(filesUploadHandler(vertx));

    router.get("/api/v1/file").handler(authenticationHandler);
    router.get("/api/v1/file").handler(metricsHandler);
    //router.get("/api/v1/file").handler(smallBodyHandler);
    router.get("/api/v1/file").handler(fileUploadHandler(vertx));

    return router;
  }

  @NotNull
  private Handler<RoutingContext> filesUploadHandler(Vertx vertx) {
    return routingContext -> {

      Integer[] pg = new Integer[1];
      Long[] since = new Long[1];
      since[0] = null;
      String[] order = new String[1];
      order[0] = null;

      pg[0] = 1;
      if (routingContext.request().getParam("pg") != null) {
        pg[0] = Integer.decode(routingContext.request().getParam("pg"));
      }
      
      if (routingContext.request().getParam("since") != null) {
        since[0] = Long.decode(routingContext.request().getParam("since"));
      }

      if (routingContext.request().getParam("order") != null) {
        order[0] = routingContext.request().getParam("order");
      }
      //If since is given then default order is asc
      if (since[0] != null && order[0] == null) {
        order[0] = "asc";
      } else if (since[0] == null && order[0] == null) { //If since is null the default order is desc
        order[0] = "desc";
      }

      Long studyId = Valid.nonNull((Long) routingContext.get("studyId"),"studyId cannot be null");
      String sunetId = Valid.nonNull(routingContext.get("sunetId"),"sunetId cannot be null");
      Integer pageSize = config.getInteger("pagesize", 100);
      Integer offset = ((pg[0] - 1) * pageSize);
      Integer fetchSize = pageSize + 1;

      //get a chunk of files that match the since and order provided

      dbb.transactAsync(dbp -> {
        // Now get file upload sequences for this participant 
        Sql query = null;
        List<JsonObject> fileUploadSeqs = null;
        if (since[0] == null) {
          query = getFilesQuery(since[0], order[0]);
          fileUploadSeqs = dbp.get()
              .toSelect(query)
              .argInteger(offset).argInteger(fetchSize).queryMany((r) -> {
                JsonObject obj = new JsonObject();
                obj.put("uploaded",
                    DateTimeFormatter.ISO_INSTANT
                        .format(r.getDateOrNull("completed_time").toInstant()));
                obj.put("sequence", r.getLongOrNull("mh_upload_sequence"));
                Long mhDeviceAppId = r.getLongOrNull("mh_device_app_id");
                //get userId from deviceId
                Long mhProfileId = dbp.get()
                    .toSelect("select mh_user_profile_id from mh_device_app where mh_device_app_id = ?")
                    .argLong(mhDeviceAppId).queryLongOrNull();
                Long usrId = dbp.get().toSelect("select user_rpid from mh_user_profile where mh_user_profile_id = ?")
                    .argLong(mhProfileId).queryLongOrNull();
                obj.put("participantId", usrId);
                return obj;
              });
        } else  {
          query = getFilesQuery(since[0], order[0]);
          fileUploadSeqs = dbp.get()
              .toSelect(query)
              .argLong(since[0])
              .argInteger(offset).argInteger(fetchSize).queryMany((r) -> {
                JsonObject obj = new JsonObject();
                obj.put("uploaded",
                    DateTimeFormatter.ISO_INSTANT
                        .format(r.getDateOrNull("completed_time").toInstant()));
                obj.put("sequence", r.getLongOrNull("mh_upload_sequence"));
                Long mhDeviceAppId = r.getLongOrNull("mh_device_app_id");
                //get userId from deviceId
                Long mhProfileId = dbp.get()
                    .toSelect("select mh_user_profile_id from mh_device_app where mh_device_app_id = ?")
                    .argLong(mhDeviceAppId).queryLongOrNull();
                Long usrId = dbp.get().toSelect("select user_rpid from mh_user_profile where mh_user_profile_id = ?")
                    .argLong(mhProfileId).queryLongOrNull();
                obj.put("participantId", usrId);
                return obj;
              });
        }
        return fileUploadSeqs;
      } , result -> {
        if (result.succeeded()) {
          List<JsonObject> fullParticipantsFilesList = result.result();
          boolean nextPage = (fullParticipantsFilesList.size() > pageSize);
          final List<JsonObject> participantsFilesList;
          if (nextPage) {
            participantsFilesList = fullParticipantsFilesList.subList(0, fullParticipantsFilesList.size() - 1);
          } else {
            participantsFilesList = fullParticipantsFilesList;
          }
          List<JsonObject> participants = new ArrayList<>();
          List<JsonObject> deleteList = new ArrayList<>();
          HttpClient client = vertx.createHttpClient();
          //We need to create a list of unique participants to which all these files belong to
          participantsFilesList.forEach((l) -> {
            JsonObject participant = new JsonObject();
            participant.put("userId",l.getLong("participantId"));
            if (!participants.contains(participant)) {
                 participants.add(participant);
            }
          });
            JsonObject inputArgs = new JsonObject();
            inputArgs.put("sunetId", sunetId);
            inputArgs.put("studyId", studyId);
            inputArgs.put("users", participants);
          //Now find out if these unique participants share their files with the reasearcher
            client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/participantsShare",
                response -> {
              if (response.statusCode() == HttpResponseStatus.OK.code()) {
                // We need to go over the list and figure out which participants are not sharing than remove those files
                // from participantsFilesList
                response.bodyHandler(responseBody -> {
                JsonArray participantShareInfo = null;
                participantShareInfo = responseBody.toJsonArray();
                for (int i = 0; i < participantShareInfo.size(); i++) {
                  JsonObject user = participantShareInfo.getJsonObject(i);
                  //This participant does not share the file with the researcher
                  //Loop through the participantsFilesList to find all the files for this participant and
                  // add them to the delete list
                  if (!user.getBoolean("shares")) {
                     participantsFilesList.forEach((l) -> {
                      //check if the participant in the fileList object is same as the user
                      //If so add to the delete list
                      if (l.getLong("participantId").equals(user.getLong("userId"))) {
                        deleteList.add(l);
                      }
                    });
                  }
                }
                participantsFilesList.removeAll(deleteList);
                  if (participantsFilesList.size() == 0 && nextPage) {
                    //None of the files from the initial lot matched the access level for the user so get another chcunk of
                    //files so that we do not return an empty list to the user.
                    getUploadedFiles(since[0], order[0], pg[0] + 1,sunetId, studyId,routingContext, vertx);
                  } else {
                    // construct the result json
                    JsonObject fileUploadResult = new JsonObject();
                    fileUploadResult.put("currentPage", pg[0]);
                    fileUploadResult.put("nextPage", nextPage);
                    List<JsonObject> dataUrlList = new ArrayList<>();
                    JsonObject uploadObj = null;
                    for (JsonObject aParticipantsFilesList : participantsFilesList) {
                      uploadObj = aParticipantsFilesList;
                      JsonObject dataUrl = new JsonObject();
                      dataUrl.put("fileUploadUrl",
                          config.getString("mh.upload.url") + "?sequence=" + uploadObj.getLong("sequence"));
                      dataUrl.put("sequence", uploadObj.getLong("sequence"));
                      dataUrl.put("uploaded", uploadObj.getString("uploaded"));
                      dataUrl.put("participantId", uploadObj.getLong("participantId"));
                      dataUrlList.add(dataUrl);
                    }
                    fileUploadResult.put("dataUrls", dataUrlList);
                    log.debug("Successfully returned the files result");
                    routingContext.response().setStatusCode(HttpResponseStatus.OK.code()).end(Json.encode(fileUploadResult));
                  }
              });
              } else if (response.statusCode() != HttpResponseStatus.OK.code()) {
                log.debug("Failed to get the files  ", result.cause());
                routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
              }

            }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
                .end(inputArgs.encodePrettily());
          } else {
          log.debug("Failed to get the files  ", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        }

      });
    };
  }

  private void getUploadedFiles(Long since, String order, Integer pg,String sunetId, Long studyId, RoutingContext routingContext, Vertx vertx) {

    //get a chunk of files that match the since and order provided
    Integer pageSize = config.getInteger("pagesize", 100);
    Integer offset = ((pg - 1) * pageSize);
    Integer fetchSize = pageSize + 1;

    dbb.transactAsync(dbp -> {
      // Now get file upload sequences for this participant
      Sql query = null;
      List<JsonObject> fileUploadSeqs = null;
      if (since == null) {
        query = getFilesQuery(since, order);
        fileUploadSeqs = dbp.get()
            .toSelect(query)
            .argInteger(offset).argInteger(fetchSize).queryMany((r) -> {
              JsonObject obj = new JsonObject();
              obj.put("uploaded",
                  DateTimeFormatter.ISO_INSTANT
                      .format(r.getDateOrNull("completed_time").toInstant()));
              obj.put("sequence", r.getLongOrNull("mh_upload_sequence"));
              Long mhDeviceAppId = r.getLongOrNull("mh_device_app_id");
              //get userId from deviceId
              Long mhProfileId = dbp.get()
                  .toSelect("select mh_user_profile_id from mh_device_app where mh_device_app_id = ?")
                  .argLong(mhDeviceAppId).queryLongOrNull();
              Long usrId = dbp.get().toSelect("select user_rpid from mh_user_profile where mh_user_profile_id = ?")
                  .argLong(mhProfileId).queryLongOrNull();
              obj.put("participantId", usrId);
              return obj;
            });
      } else  {
        query = getFilesQuery(since, order);
        fileUploadSeqs = dbp.get()
            .toSelect(query)
            .argLong(since)
            .argInteger(offset).argInteger(fetchSize).queryMany((r) -> {
              JsonObject obj = new JsonObject();
              obj.put("uploaded",
                  DateTimeFormatter.ISO_INSTANT
                      .format(r.getDateOrNull("completed_time").toInstant()));
              obj.put("sequence", r.getLongOrNull("mh_upload_sequence"));
              Long mhDeviceAppId = r.getLongOrNull("mh_device_app_id");
              //get userId from deviceId
              Long mhProfileId = dbp.get()
                  .toSelect("select mh_user_profile_id from mh_device_app where mh_device_app_id = ?")
                  .argLong(mhDeviceAppId).queryLongOrNull();
              Long usrId = dbp.get().toSelect("select user_rpid from mh_user_profile where mh_user_profile_id = ?")
                  .argLong(mhProfileId).queryLongOrNull();
              obj.put("participantId", usrId);
              return obj;
            });
      }
      return fileUploadSeqs;
    } , result -> {
      if (result.succeeded()) {
        List<JsonObject> fullParticipantsFilesList = result.result();
        boolean nextPage = (fullParticipantsFilesList.size() > pageSize);
        final List<JsonObject> participantsFilesList;
        if (nextPage) {
          participantsFilesList = fullParticipantsFilesList.subList(0, fullParticipantsFilesList.size() - 1);
        } else {
          participantsFilesList = fullParticipantsFilesList;
        }
        List<JsonObject> participants = new ArrayList<>();
        List<JsonObject> deleteList = new ArrayList<>();
        HttpClient client = vertx.createHttpClient();
        //We need to create a list of unique participants to which all these files belong to
        participantsFilesList.forEach((l) -> {
          JsonObject participant = new JsonObject();
          participant.put("userId",l.getLong("participantId"));
          if (!participants.contains(participant)) {
            participants.add(participant);
          }
        });
        JsonObject inputArgs = new JsonObject();
        inputArgs.put("sunetId", sunetId);
        inputArgs.put("studyId", studyId);
        inputArgs.put("users", participants);
        //Now find out if these unique participants share their files with the reasearcher
        client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/participantsShare",
            response -> {
              if (response.statusCode() == HttpResponseStatus.OK.code()) {
                // We need to go over the list and figure out which participants are not sharing than remove those files
                // from participantsFilesList
                response.bodyHandler(responseBody -> {
                  JsonArray participantShareInfo = null;
                  participantShareInfo = responseBody.toJsonArray();
                  for (int i = 0; i < participantShareInfo.size(); i++) {
                    JsonObject user = participantShareInfo.getJsonObject(i);
                    //This participant does not share the file with the researcher
                    //Loop through the participantsFilesList to find all the files for this participant and
                    // add them to the delete list
                    if (!user.getBoolean("shares")) {
                      participantsFilesList.forEach((l) -> {
                        //check if the participant in the fileList object is same as the user
                        //If so add to the delete list
                        if (l.getLong("participantId").equals(user.getLong("userId"))) {
                          deleteList.add(l);
                        }
                      });
                    }
                  }
                  participantsFilesList.removeAll(deleteList);
                  if (participantsFilesList.size() == 0 && nextPage) {
                    //None of the files from the initial lot matched the access level for the user so get another chcunk of
                    //files so that we do not return an empty list to the user.
                    getUploadedFiles(since, order, pg + 1,sunetId, studyId,routingContext, vertx);
                  } else {
                    // construct the result json
                    JsonObject fileUploadResult = new JsonObject();
                    fileUploadResult.put("currentPage", pg);
                    fileUploadResult.put("nextPage", nextPage);
                    List<JsonObject> dataUrlList = new ArrayList<>();
                    JsonObject uploadObj = null;
                    for (JsonObject aParticipantsFilesList : participantsFilesList) {
                      uploadObj = aParticipantsFilesList;
                      JsonObject dataUrl = new JsonObject();
                      dataUrl.put("fileUploadUrl",
                          config.getString("mh.upload.url") + "?sequence=" + uploadObj.getLong("sequence"));
                      dataUrl.put("sequence", uploadObj.getLong("sequence"));
                      dataUrl.put("uploaded", uploadObj.getString("uploaded"));
                      dataUrl.put("participantId", uploadObj.getLong("participantId"));
                      dataUrlList.add(dataUrl);
                    }
                    fileUploadResult.put("dataUrls", dataUrlList);
                    log.debug("Successfully returned the files result");
                    routingContext.response().setStatusCode(HttpResponseStatus.OK.code()).end(Json.encode(fileUploadResult));
                  }
                });
              } else if (response.statusCode() != HttpResponseStatus.OK.code()) {
                log.debug("Failed to get the files  ", result.cause());
                routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
              }

            }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
            .end(inputArgs.encodePrettily());
      } else {
        log.debug("Failed to get the files  ", result.cause());
        routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
      }
    });

  }

   private Sql getFilesQuery(Long since, String order) {

    Sql query = null;
    if (since == null && order.equals("asc")) {
      query = new Sql(
          "select mh_upload_sequence,completed_time,mh_device_app_id from mh_file_upload where mh_upload_sequence is not null  order by mh_upload_sequence asc offset (?) rows fetch first (?) rows only");
    } else if (since == null && order.equals("desc")) {
      query = new Sql(
          "select mh_upload_sequence,completed_time,mh_device_app_id from mh_file_upload where mh_upload_sequence is not null order by mh_upload_sequence desc offset (?) rows fetch first (?) rows only");
    } else if (since != null && order.equals("asc")) {
      query = new Sql(
          "select mh_upload_sequence,completed_time,mh_device_app_id from mh_file_upload where mh_upload_sequence is not null and mh_upload_sequence > ? order by mh_upload_sequence asc offset (?) rows fetch first (?) rows only");
    } else if (since != null && order.equals("desc")) {
      query = new Sql(
          "select mh_upload_sequence,completed_time,mh_device_app_id from mh_file_upload where mh_upload_sequence is not null and mh_upload_sequence > ? order by mh_upload_sequence desc offset (?) rows fetch first (?) rows only");
    }
    return query;
  }

  public void uploadSequenceHandler(Handler<AsyncResult<String>> resultHandler) {
    // assigning the mh_upload_sequence to the uploaded files

    dbb.transactAsync(dbp -> {
      List<Long> fileUploadIds = null;
      // Check whether we have assigned sequences before and get the max uploadSequence
      Long uploadSeq =
          dbp.get().toSelect("select max(mh_upload_sequence) from mh_file_upload")
              .queryLongOrNull();
      // This is the first run
      if (uploadSeq == null) {
        log.debug("Running the uploadSequenceHandler for first time");
        fileUploadIds = dbp.get()
            .toSelect(
                "select mh_file_upload_id from mh_file_upload where completed_time is not null and completed_time <= ? and mh_upload_sequence is null order by completed_time")
            .argDateNowPerDb().<Long>queryMany((r) -> {
          return r.getLongOrNull();
        });
      } else {
        // We have run before till the completed_time of the max(mh_upload_sequence)
        Date lastCheckedTime = dbp.get()
            .toSelect("select completed_time from mh_file_upload where mh_upload_sequence = ?")
            .argLong(uploadSeq).queryDateOrNull();
        log.debug("The last completed_time for uploadSequemceHandler was " + lastCheckedTime);
        fileUploadIds = dbp.get()
            .toSelect(
                "select mh_file_upload_id from mh_file_upload where completed_time is not null and completed_time + interval '5' minute >=  ? and mh_upload_sequence is null order by completed_time")
            .argDate(lastCheckedTime).queryMany((r) -> {
          return r.getLongOrNull();
        });
      }
      // Now go over the fileUploadIds and assign the mh_upload_sequence to them
      for (Long fileId : fileUploadIds) {

        dbp.get()
            .toUpdate("update  mh_file_upload set mh_upload_sequence = "
                + dbp.get().flavor().sequenceNextVal("mh_upload_seq")
                + " where mh_file_upload_id = ?")
            .argLong(fileId).update(1);
      }

      return null;
    } , result -> {
      if (result.succeeded()) {
        log.debug("Updated the upload sequence ");
        resultHandler.handle(Future.succeededFuture("uploadSequenceHandler ran successfully"));
      }
      if (result.failed()) {
        log.debug("Failed to updated the upload sequence ", result.cause());
        resultHandler.handle(Future.failedFuture("Failed to updated the upload sequence"));
      }

    });
  }

  @NotNull
  private Handler<RoutingContext> participantsHandler(Vertx vertx) {
    return routingContext -> {
      Integer[] pg = new Integer[1];
      Long[] sequence = new Long [1];
      sequence[0] = null;
      String[] order = new String[1];
      order[0] = "desc";
      pg[0] = 1;
      if (routingContext.request().getParam("pg") != null) {
        pg[0] = Integer.decode(routingContext.request().getParam("pg"));
      }
      //check if the sequence is provided then we only need changed participants
      if (routingContext.request().getParam("sequence") != null) {
        sequence[0] = Long.decode(routingContext.request().getParam("sequence"));
      }
      if (routingContext.request().getParam("order") != null) {
        order[0] = routingContext.request().getParam("order");
      }
      Long studyId = Valid.nonNull((Long) routingContext.get("studyId"), "studyId cannot be null");
      String sunetId = Valid.nonNull(routingContext.get("sunetId"), "sunetId cannot be null");
      JsonObject inputArgs = new JsonObject();
      inputArgs.put("pg", pg[0]);
      inputArgs.put("studyId", studyId);
      inputArgs.put("sunetId", sunetId);
      inputArgs.put("sequence", sequence[0]);
      inputArgs.put("order", order[0]);
      HttpClient client = vertx.createHttpClient();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/participants",
          response -> {
        if (response.statusCode() == HttpResponseStatus.OK.code()) {
          response.bodyHandler(responseBody -> {
            JsonArray userIds = null;
            Integer pageSize = config.getInteger("pagesize", 100);
            userIds = responseBody.toJsonArray();
            // Check if we have next page
            boolean nextPage = (userIds.size() > pageSize);
            // construct the result json
            JsonObject participantsResult = new JsonObject();
            JsonObject meta = new JsonObject();
            meta.put("currentPage", pg[0]);
            meta.put("nextPage", nextPage);
            meta.put("pageSize", pageSize);
            participantsResult.put("meta", meta);
            if (nextPage) {
              participantsResult.put("Participants", userIds.getList().subList(0, userIds.size() - 1));
            } else {
              participantsResult.put("Participants", userIds.getList());
            }
            log.debug("Successfully returned the participant result");
            routingContext.response().setStatusCode(HttpResponseStatus.OK.code()).end(Json.encode(participantsResult));
          });
        } else {
          log.debug("Failed to return the participant result ");
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
            }
      }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .end(inputArgs.encodePrettily());
    };
  }

  @NotNull
  private Handler<RoutingContext> fileUploadHandler(Vertx vertx) {
    return routingContext -> {
      Long sequence = Long.decode(Valid.nonNull(routingContext.request().getParam("sequence"),"sequence cannot be null"));
      Long studyId = Valid.nonNull((Long) routingContext.get("studyId"),"studyId cannot be null");
      String sunetId = Valid.nonNull(routingContext.get("sunetId"),"sunetId cannot be null");
      boolean decrypt = encryptionEnabled && !"no".equals(routingContext.request().getParam("decrypt"));
      RecipientInfo decryptRecipientRequested = recipientsByVersion.get(routingContext.request().getParam("decrypt"));
      Valid.isFalse(decrypt && routingContext.request().getParam("decrypt") != null
          && decryptRecipientRequested == null, "Unsupported value for the 'decrypt' query parameter");
      //get the user_rpid from the sequence
      dbb.transactAsync(dbp -> {
        return dbp.get().toSelect("select  c.user_rpid  from mh_file_upload a, mh_device_app b, "
            + "mh_user_profile c where a.mh_upload_sequence = ? "
            + "and a.mh_device_app_id = b.mh_device_app_id and b.mh_user_profile_id = c.mh_user_profile_id")
            .argLong(sequence).queryLongOrNull();
      },result -> {
        if (result.succeeded()) {
          log.debug("Successfully retrieved the userRpid for the file upload sequence");
          Buffer buf = Buffer.buffer();
          //Build the input arguments to pass to the api end point
          JsonObject inputArgs = new JsonObject();
          inputArgs.put("sunetId", sunetId);
          inputArgs.put("studyId", studyId);
          ArrayList<JsonObject> userL = new ArrayList<JsonObject>();
          JsonObject user = new JsonObject();
          user.put("userId", result.result());
          userL.add(user);
          inputArgs.put("users", userL);

          Metric metric = new Metric(log.isDebugEnabled());
          HttpClient client = vertx.createHttpClient();
          client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/participantsShare",
              response -> {
                metric.checkpoint("response", response.statusCode());
            //make sure that the participants share is set to true
            if (response.statusCode() == HttpResponseStatus.OK.code()) {
              response.bodyHandler(responseBody -> {
                try {
                  metric.checkpoint("body", responseBody.length());
                  JsonArray users = responseBody.toJsonArray();
                  if (users.getJsonObject(0).getBoolean("shares")) {
                    dbb.transactAsync(dbp -> {
                      Long fileUploadId = dbp.get()
                          .toSelect("select mh_file_upload_id from mh_file_upload where mh_upload_sequence = ?")
                          .argLong(sequence).queryLongOrNull();
                      if (fileUploadId != null) {
                        byte[] encryptedContent = dbp.get()
                            .toSelect("select content from mh_file_upload_content where mh_file_upload_id = ?")
                            .argLong(fileUploadId).query(rs -> {
                              if (rs.next()) {
                                return rs.getBlobBytesOrZeroLen();
                              }
                              return new byte[0];
                            });
                        if (decrypt) {
                          // Decrypt it
                          RecipientInfo decryptRecipient = decryptRecipientRequested;
                          CMSEnvelopedData envelopedData;
                          try {
                            envelopedData = new CMSEnvelopedData(encryptedContent);
                          } catch (CMSException e) {
                            log.debug("Looks like content was not encrypted - returning raw content", e);
                            buf.appendBytes(encryptedContent);
                            return buf;
                          }
                          RecipientInformation recInfo = null;
                          if (decryptRecipient != null) {
                            // Client explicitly requested a particular version
                            recInfo = envelopedData.getRecipientInfos().get(decryptRecipient.recipientId);
                          }
                          if (recInfo == null) {
                            // Fall back to searching for a recipient to decrypt
                            for (RecipientInformation ri : envelopedData.getRecipientInfos()) {
                              if (recipientsById.containsKey(ri.getRID())) {
                                decryptRecipient = recipientsById.get(ri.getRID());
                                recInfo = envelopedData.getRecipientInfos().get(decryptRecipient.recipientId);
                                break;
                              }
                            }
                          }
                          if (recInfo == null) {
                            // We can't find any recipient, so give the client the encrypted content
                            // (assume they are handling the decryption themselves)
                            buf.appendBytes(encryptedContent);
                          } else {
                            buf.appendBytes(recInfo.getContent(decryptRecipient.recipient));
                          }
                        } else {
                          buf.appendBytes(encryptedContent);
                        }
                      }
                      return buf;
                    }, result1 -> {
                      if (buf.length() > 0) {
                        log.debug("Successfully uploaded the file");
                        routingContext.response().setStatusCode(HttpResponseStatus.OK.code()).end(buf);
                      } else {
                        log.warn("Failed to upload the file for the given sequence", result1.cause());
                        routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
                      }
                    });
                  } else {
                    //The participants sharing scope does not match the data_sharing for the sunet id. So return unauthorized code
                    log.debug("The sharing scope for participant and the researcher does not match");
                    routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code()).end();
                  }
                } finally {
                  if (log.isDebugEnabled()) {
                    log.debug("Call participantsShare: " + metric.getMessage());
                  }
                }
              });
            } else if (response.statusCode() != HttpResponseStatus.OK.code()) { //The participants sharing scope does not match the data_sharing for the sunet id. So return unauthorized code
              log.debug("Error retrieving information about participant share");
              routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
            }
          }).exceptionHandler(exception -> {
            log.error("The participantsShare api returned error", exception);
            routingContext.response().setStatusCode(500).end();
          }).putHeader("content-type", "application/json")
              .end(inputArgs.encode());
        } else {
          log.warn("Failed to upload the file for the given sequence", result.cause());
          routingContext.response().setStatusCode(500).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> refreshTokenHandler(Vertx vertx) {
    return routingContext -> {
      Valid.formAttributeEqualsShow(routingContext, "grant_type", "refresh_token");
      String token = Valid.safeFormAttributeReq(routingContext, "refresh_token");

      HttpClient client = vertx.createHttpClient();
      client.post(portalApiPort, portalApiHost, portalApiContext + "/api/v1/refreshApiToken",
          response -> {
        if (response.statusCode() == HttpResponseStatus.OK.code()) {
          response.bodyHandler(responseBody -> {
            JsonObject responseJson = new JsonObject(responseBody.toString());
            //Generate the random key.
            String sToken = new SessionKeyGenerator(secureRandom).create(64);
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            String uncryptedToken = sToken.substring(0, sToken.length() / 2);
            String bToken = sToken.substring(sToken.length() / 2);
            String bcryptedToken = OpenBSDBCrypt.generate(bToken.toCharArray(),salt,13);
            //Now insert this new token into sessionToken tables.First check if the access_token for this sunet_id 
            // does not already exists.If it already exists than you need to replace else insert.
              dbb.transactAsync(dbp -> {
              Long updateSeq = dbp.get().toSelect("select update_sequence from mh_access_token where sunet_id =?")
                  .argString(responseJson.getString("rp_sunet_id")).queryLongOrNull();
              Long newSequence = 0L;
              if (updateSeq != null) {
                newSequence = updateSeq + 1;
                //This means that sunet_id exists so we delete it and then insert new one in both the
                //access_token and access_token_history table
                Sql sql = new Sql();
                sql.append("insert into mh_access_token_history (update_time,update_sequence,is_deleted,uncrypted_token,bcrypted_token,sunet_id,study_id,org_id,valid_from,valid_thru) "
                    + "(select ? as update_time, " );
                sql.append(newSequence);
                sql.append(" as update_sequence, ? as is_deleted, uncrypted_token,bcrypted_token,sunet_id,study_id,org_id,valid_from,valid_thru from mh_access_token where sunet_id = ?)");
                dbp.get().toInsert(sql).argDateNowPerDb().argBoolean(true)
                    .argString(responseJson.getString("rp_sunet_id")).insert(1);
                dbp.get().toDelete("delete from mh_access_token where sunet_id = ?")
                    .argString(responseJson.getString("rp_sunet_id")).update(1);
                newSequence++;
              }
              Sql sql1 = new Sql();
              sql1.append(
                  "insert into mh_access_token (uncrypted_token,bcrypted_token,sunet_id,study_id,org_id,valid_from,valid_thru,update_time,update_sequence) values(?,:secret_bcrypt,?,?,?,?,(  ? + (interval '");
              sql1.append(1);
              sql1.append("' day)),?,?)");
              //Now insert into both the mh_access_token and mh_access_token_history tables
              dbp.get().toInsert(sql1)
                  .argString(uncryptedToken).argString("secret_bcrypt", bcryptedToken)
                  .argString(responseJson.getString("rp_sunet_id"))
                  .argLong(responseJson.getLong("rp_study_id")).argLong(responseJson.getLong("rp_org_id"))
                  .argDateNowPerDb().argDateNowPerDb()
                  .argDateNowPerDb()
                  .argLong(newSequence).insert(1);
              Sql sql2 = new Sql();
              sql2.append(
                  "insert into mh_access_token_history (uncrypted_token,bcrypted_token,sunet_id,study_id,org_id,valid_from,valid_thru,update_time,update_sequence) values(?,:secret_bcrypt,?,?,?,?,(  ? + (interval '");
              sql2.append(1);
              sql2.append("' day)),?,?)");
              dbp.get().toInsert(sql2)
                  .argString(uncryptedToken).argString("secret_bcrypt", bcryptedToken)
                  .argString(responseJson.getString("rp_sunet_id"))
                  .argLong(responseJson.getLong("rp_study_id"))
                  .argLong(responseJson.getLong("rp_org_id")).argDateNowPerDb().argDateNowPerDb()
                  .argDateNowPerDb()
                  .argLong(newSequence).insert(1);
              return sToken;
            } , result -> {
              if (result.succeeded()) {
                responseJson.remove("rp_study_id");
                responseJson.remove("rp_sunet_id");
                responseJson.remove("rp_org_id");
                responseJson.put("access_token", result.result());
                responseJson.put("token_type", "bearer");
                responseJson.put("expires_in", 60 * 60 * 24L);
                routingContext.response().setStatusCode(HttpResponseStatus.OK.code())
                    .putHeader("content-type", "application/json")
                    .end(responseJson.encode());
              } else {
                log.error("unable to create access token", result.cause());
                routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
              }
            });
          });
        } else if (response.statusCode() == HttpResponseStatus.UNAUTHORIZED.code()) {
          routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
              .putHeader("content-type", "application/json")
              .end("{\"message\":\" Please check the  token is valid and not expired.Get the Api token again\"}");
        } else {
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code())
              .putHeader("content-type", "application/json")
              .end("{\"message\":\" Could not get refresh token\"}");
        }

      }).exceptionHandler(routingContext::fail).putHeader("content-type", "application/json")
          .end(new JsonObject().put("token", token).encodePrettily());
    };
  }

  private void fail(RoutingContext rc) {
    if (isOrCausedBy(rc.failure(), BadRequestException.class)) {
      log.debug("Validation error", rc.failure());
      rc.response().setStatusCode(400).end(rc.failure().getMessage());
    } else {
      log.error("Unexpected error", rc.failure());
      rc.response().setStatusCode(500).end();
    }
  }

  private boolean isOrCausedBy(Throwable top, Class<? extends Throwable> type) {
    for (Throwable t : ExceptionUtils.getThrowables(top)) {
      if (type.isAssignableFrom(t.getClass())) {
        return true;
      }
    }
    return false;
  }

  private static class RecipientInfo {
    final RecipientId recipientId;
    final Recipient recipient;

    public RecipientInfo(RecipientId recipientId, Recipient recipient) {
      this.recipientId = recipientId;
      this.recipient = recipient;
    }
  }
}
