package com.github.susom.mhealth.server.apis;

import com.github.susom.database.Config;
import com.github.susom.database.Database;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.Metric;
import com.github.susom.database.Sql;
import com.github.susom.database.VertxUtil;
import com.github.susom.mhealth.server.apis.SageApi.StudyParticipant;
import com.github.susom.mhealth.server.services.Consent;
import com.github.susom.mhealth.server.services.GenePoolConsent;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.ApiToken;
import com.github.susom.mhealth.server.services.MyPartDao.ShareInfo;
import com.github.susom.mhealth.server.services.MyPartDao.Token;
import com.github.susom.mhealth.server.services.SessionKeyGenerator;
import com.github.susom.mhealth.server.services.SharingScope;
import com.github.susom.mhealth.server.services.Util;
import com.github.susom.vertx.base.BadRequestException;
import com.github.susom.vertx.base.MetricsHandler;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.Valid;
import com.lowagie.text.DocumentException;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xhtmlrenderer.pdf.ITextRenderer;

import static com.github.susom.mhealth.server.container.ParticipantPortal.loadResource;

/**
 * Expose an API to be used by server applications such as the MyHeart
 * Counts API server.
 *
 * @author garricko
 */
public class PortalServerApi {
  private static final Logger log = LoggerFactory.getLogger(PortalServerApi.class);
  private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("MMMM d, yyyy");
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final Mailer mailer;
  private final Config config;
  private final SageApi sageApi;
  private static final String ASSENT_EMAIL_SUBJECT = "Assent Agreement for GenePool Study";

  public PortalServerApi(Builder dbb, SecureRandom secureRandom, Mailer mailer, Config config, SageApi sageApi) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.mailer = mailer;
    this.config = config;
    this.sageApi = sageApi;
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {

    // TODO authenticate to determine the server app/study
    MetricsHandler metricsHandler = new MetricsHandler(secureRandom, config.getBooleanOrFalse("log.full.requests"));
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    router.post("/api/v1/register").handler(metricsHandler);
    router.post("/api/v1/register").handler(smallBodyHandler);
    router.post("/api/v1/register").handler(registerHandler(vertx));

    router.post("/api/v1/refreshApiToken").handler(metricsHandler);
    router.post("/api/v1/refreshApiToken").handler(smallBodyHandler);
    router.post("/api/v1/refreshApiToken").handler(refreshApiTokenHandler());

    router.post("/api/v1/participants").handler(metricsHandler);
    router.post("/api/v1/participants").handler(smallBodyHandler);
    router.post("/api/v1/participants").handler(participantsHandler());

    router.post("/api/v1/participantsShare").handler(metricsHandler);
    router.post("/api/v1/participantsShare").handler(smallBodyHandler);
    router.post("/api/v1/participantsShare").handler(participantsShareHandler());

    router.post("/api/v1/login").handler(metricsHandler);
    router.post("/api/v1/login").handler(smallBodyHandler);
    router.post("/api/v1/login").handler(loginHandler());

    router.post("/api/v1/resendEmailVerification").handler(metricsHandler);
    router.post("/api/v1/resendEmailVerification").handler(smallBodyHandler);
    router.post("/api/v1/resendEmailVerification").handler(resendEmailVerificationHandler(vertx));

    router.post("/api/v1/dataSharing").handler(metricsHandler);
    router.post("/api/v1/dataSharing").handler(smallBodyHandler);
    router.post("/api/v1/dataSharing").handler(dataSharingHandler());

    router.post("/api/v1/auth/withdraw").handler(metricsHandler);
    router.post("/api/v1/auth/withdraw").handler(smallBodyHandler);
    router.post("/api/v1/auth/withdraw").handler(withdrawHandler());

    router.post("/api/v1/createConsent").handler(metricsHandler);
    router.post("/api/v1/createConsent").handler(smallBodyHandler);
    router.post("/api/v1/createConsent").handler(consentHandler());

    return router;
  }

  private void createConsent(Supplier<Database> dbp, Long studyId, Consent consent, String studyShortName) throws Exception {
    String html = loadResource(studyShortName + "/consentAgreement.html");
    if (html == null) {
      html = loadResource("default/consentAgreement.html");
    }
    SharingScope sharingLabel = SharingScope.valueOf(consent.getScope().toUpperCase());
    HashMap<String, String> map = new HashMap<>();
    map.put("participant.name", consent.getName());
    map.put("participant.signing.date", consent.getSigningDate());
    map.put("participant.email", consent.getEmail());
    map.put("participant.sharing", sharingLabel.getLabel());

    String completeHtmlConsent = Util.resolveHtmlTemplate(html, map);
    final byte[] pdfBytes = createPdfDoc(completeHtmlConsent);
    consent.setHtmlConsent(completeHtmlConsent);
    consent.setPdfConsent(pdfBytes);
    JsonObject studyObj = dbp.get().toSelect(
        "select rp_study_support_email,rp_study_email_subject from rp_study where rp_study_id = ?")
        .argLong(studyId).<JsonObject>query(
            (r) -> {
              JsonObject row = null;
              if (r.next()) {
                row = new JsonObject();
                row.put("rp_study_support_email", r.getStringOrNull("rp_study_support_email"));
                row.put("rp_study_email_subject", r.getStringOrNull("rp_study_email_subject"));
              }
              return row;
            });
    mailer.sendAttachment(studyObj.getString("rp_study_support_email"), null, consent.getEmail(), null, null,
        studyObj.getString("rp_study_email_subject"), completeHtmlConsent, pdfBytes);
  }

  private void createGenePoolConsent(Supplier<Database> dbp, GenePoolConsent consent, String email, Long rpStudyId, String signingDate) throws Exception {

    InputStream inS = Thread.currentThread().getContextClassLoader().getResourceAsStream("genepool/consentAgreement.html");
    Scanner scn = new Scanner(inS);
    String consentFull = scn.useDelimiter("\\Z").next();
    scn.close();

    HashMap<String, String> map = new HashMap<>();


    if (consent.getAssentAdultName() != null) {
      map.put("participant.adult", "");
      map.put("participant.parent", "X");
    } else {
      map.put("participant.adult", "X");
      map.put("participant.parent", "");
    }

    //put the adult name and current date in map
    map.put("participant.name", consent.getParticipantName());
    map.put("participant.adultSigning.date", signingDate);

    if (consent.getAssentChildName() != null) {
      //make sure that participant.parent is set
      Valid.isFalse(consent.getChildCannotAssent(), "Child cannot assent has to be false, if child name is provided");
      map.put("participant.childName", consent.getAssentChildName());
    } else {
      map.put("participant.childName", "");
    }
    if (consent.getShareWithNih() != null) {
      if (consent.getShareWithNih() == true) {
        map.put("participant.YesNIH", "X");
        map.put("participant.NoNIH", "");
      } else {
        map.put("participant.YesNIH", "");
        map.put("participant.NoNIH", "X");
      }
    }
    //The reason we check null is because the following fields are optional in requirement. in order to allow front end change freely in the future
    // we do not throw the exception in case the following fields not passed from frontend since they are optional
    //Valid.isFalse throws exceptions, given the below fields are optional. we should skip the logic if it is null.
    if (consent.getTreatableGeneticFindings() != null) {
      if (consent.getTreatableGeneticFindings() == true) {
        Valid.isFalse(consent.getBothGeneticFindings(), "When treatable findings is true, both genetic findings has to be false.Only one can be true.");
        Valid.isFalse(consent.getDoNotInformGeneticFindings(), "When treatable findings is true, do not inform genetic findings has to be false.Only one can be true");
        map.put("participant.YesMedTreGenFin", "X");
      } else {
        map.put("participant.YesMedTreGenFin", "");
      }
    }
    if (consent.getBothGeneticFindings() != null) {
      if (consent.getBothGeneticFindings() == true) {
        Valid.isFalse(consent.getDoNotInformGeneticFindings(), "When both genetic findings is true, do not inform genetic findings has to be false.Only one can be true");
        Valid.isFalse(consent.getTreatableGeneticFindings(), "When both genetic findings is true, treatable genetic findings has to be false.Only one can be true");
        map.put("participant.YesTreAndNonTreGenFin", "X");
      } else {
        map.put("participant.YesTreAndNonTreGenFin", "");
      }
    }

    if (consent.getDoNotInformGeneticFindings() != null) {
      if (consent.getDoNotInformGeneticFindings() == true) {
        Valid.isFalse(consent.getTreatableGeneticFindings(), "When do not inform  genetic findings is true, treatable genetic findings has to be false.Only one can be true");
        Valid.isFalse(consent.getBothGeneticFindings(), "When do not inform genetic findings is true, both genetic findings has to be false.Only one can be true");
        map.put("participant.NoGenFin", "X");
      } else {
        map.put("participant.NoGenFin", "");
      }
    }

    if (consent.getRelatedToFamilyHistory() != null) {
      if (consent.getRelatedToFamilyHistory() == true) {
        Valid.nonNull(consent.getFamilyHistoryOfDisease(), "When related to family history  is true, family history of disease cannot be null");
        Valid.isFalse(consent.getDoNotInformGeneticFindings(), "When related to family history  is true, do not inform genetic findings has to be false.Only one can be true");
        Valid.isFalse(consent.getTreatableGeneticFindings(), "When related to family history  is true, treatable genetic findings has to be false.Only one can be true");
        Valid.isFalse(consent.getBothGeneticFindings(), "When related to family history  is true, both genetic findings has to be false.Only one can be true");
        map.put("participant.YesRelGenFin", "X");
      } else {
        map.put("participant.YesRelGenFin", "");
      }
    }

    if (consent.getFamilyHistoryOfDisease() != null) {
      Valid.isTrue(consent.getRelatedToFamilyHistory(), "When family history of disease is not null, related to family history cannot be false");
      map.put("participant.FamilyHisOf", consent.getFamilyHistoryOfDisease());
    } else {
      map.put("participant.FamilyHisOf", "");
    }

    if (consent.getStanfordResearchRegistry() != null) {
      if (consent.getStanfordResearchRegistry() == true) {
        map.put("participant.YesStanReg", "X");
        map.put("participant.NoStanReg", "");
      } else {
        map.put("participant.YesStanReg", "");
        map.put("participant.NoStanReg", "X");
      }
    }


    if (consent.getReceiveBiochemicalTests() != null) {
      if (consent.getReceiveBiochemicalTests() == true) {
        map.put("participant.YesBioTest", "X");
        map.put("participant.NoBioTest", "");
      } else {
        map.put("participant.YesBioTest", "");
        map.put("participant.NoBioTest", "X");
      }
    }
    if (consent.getSubmitUrineSample() != null) {
      if (consent.getSubmitUrineSample() == true) {
        map.put("participant.YesUrineSample", "X");
        map.put("participant.NoUrineSample", "");
      } else {
        map.put("participant.YesUrineSample", "");
        map.put("participant.NoUrineSample", "X");
      }
    }
    if (consent.getStanfordResearchRegistry() != null) {
      if (consent.getStanfordResearchRegistry() == true) {
        map.put("participant.YesResearchContact", "X");
        map.put("participant.NoResearchContact", "");
      } else {
        map.put("participant.YesResearchContact", "");
        map.put("participant.NoResearchContact", "X");
      }
    }
    //
    if (consent.getParticipantName() != null) {
      map.put("participant.Agree", "X");
      map.put("participant.Disagree", "");
    } else {
      map.put("participant.Agree", "");
      map.put("participant.Disagree", "X");
    }


    map.put("participant.Name", consent.getParticipantName());

    if (consent.getAssentAdultName() != null) {
      map.put("Guardian.Name", consent.getAssentAdultName());
    } else {
      map.put("Guardian.Name", "");
    }


    String completeHtmlConsent = Util.resolveHtmlTemplate(consentFull, map);
    final byte[] pdfBytes = createPdfDoc(completeHtmlConsent);
    consent.setHtmlConsent(completeHtmlConsent);
    consent.setPdfConsent(pdfBytes);


    //get study details
    JsonObject studyObj = dbp.get().toSelect(
        "select rp_study_support_email,rp_study_email_subject from rp_study where rp_study_id = ?")
        .argLong(rpStudyId).<JsonObject>query(
            (r) -> {
              JsonObject row = null;
              if (r.next()) {
                row = new JsonObject();
                row.put("rp_study_support_email", r.getStringOrNull("rp_study_support_email"));
                row.put("rp_study_email_subject", r.getStringOrNull("rp_study_email_subject"));
              }
              return row;
            });
    mailer.sendAttachment(studyObj.getString("rp_study_support_email"), null, email, null, null,
        studyObj.getString("rp_study_email_subject"), completeHtmlConsent, pdfBytes);
  }

  private byte[] createPdfDoc(final String consentDoc) throws DocumentException {
    ByteArrayOutputStream byteArrayBld = new ByteArrayOutputStream();
    ITextRenderer renderer = new ITextRenderer();
    renderer.setDocumentFromString(consentDoc);
    renderer.layout();
    renderer.createPDF(byteArrayBld);
    return byteArrayBld.toByteArray();
  }

  private boolean sendEmail(String email, String emailToken, String studyShortName, String sender, String studyName, String sponsorName) {
    String resourceName = studyShortName + "/email-verification.txt";
    String emailHtml = loadResource(resourceName);
    if (emailHtml == null) {
      emailHtml = loadResource("default/email-verification.txt");
    }
    Map<String, String> map = new HashMap<>();
    map.put("studyName", studyName);
    map.put("url",
        config.getString("portal.email.verify.url") + "/" + emailToken);
    map.put("sponsorName", sponsorName);
    map.put("supportEmail", sender);
    String verifiedMail = Util.resolveHtmlTemplate(emailHtml, map);
    return mailer.sendHtml(sender, null, email, null, null, "Verify your Account", verifiedMail);
  }

  @NotNull
  private Handler<RoutingContext> registerHandler(Vertx vertx) {
    return routingContext -> {

      JsonObject request = routingContext.getBodyAsJson();
      String description = Valid.nonNull(request.getString("description"), "description required");
      String study = Valid.nonNull(request.getString("study"), "study required");
      String email = Valid.nonNull(request.getString("email"), "email required");

      String[] sageSession = new String[1];
      sageSession[0] = request.getString("sageSession");

      // TODO validate description
      if (!StringUtils.isAlphanumericSpace(description) || description.isEmpty()) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device description is not valid");
        log.error("Device description is not valid. Description:  " + description);
        return;
      }
      if (!EmailValidator.getInstance(false).isValid(email)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Email address is not valid");
        return;
      }
      String[] emailToken = new String[1];
      String[] deviceRpid = new String[1];
      String[] sageId = new String[1];
      String[] sageStatus = new String[1];

      Metric metric = new Metric(log.isDebugEnabled());
      //Connect to Sage to get the studyParticipant
      sageApi.getParticipants(sageSession[0], email, result -> {
        if (result.succeeded()) {
          StudyParticipant participant = result.result();
          String email2 = participant.email;
          sageStatus[0] = participant.status;
          Date createdOn = participant.createdOn;
          sageId[0] = participant.id;
          dbb.transactAsync(dbp -> {
            // Get the studyId from the database
            Long studyId = dbp.get().toSelect("select rp_study_id from rp_study where short_name = ?")
                .argString(study).queryLongOrNull();

            SessionKeyGenerator keyGenerator = new SessionKeyGenerator(secureRandom);
            deviceRpid[0] = keyGenerator.create();


            //put the database updates for verified email
            Long rpUserId = dbp.get().toSelect("select rp_user_id from rp_user_email where email_address=?")
                .argString(email.toLowerCase()).queryLongOrNull();

            if (rpUserId == null) {
              // Create a new user
              rpUserId = dbp.get().toInsert("insert into rp_user (rp_user_id) values (?)").argPkSeq("rp_pk_seq")
                  .insertReturningPkSeq("rp_user_id");

              dbp.get()
                  .toInsert("insert into rp_user_email (rp_user_email_id, rp_user_id, email_address,"
                      + " is_primary, verify_complete_time) values (?,?,?,?,?)")
                  .argPkSeq("rp_pk_seq").argLong(rpUserId).argString(email.toLowerCase()).argBoolean(true).argDateNowPerDb()
                  .insert(1);

            }
            // The same user might have enrolled for another study.Therefore userId might not be null. Therefore we need to enter
            // a row in this table.if this user for this study has not been added to rp_user_in_study
            Long user = dbp.get().toSelect("select user_rpid from rp_user_in_study where rp_user_id = ? and rp_study_id = ?")
                .argLong(rpUserId).argLong(studyId).queryLongOrNull();
            MyPartDao dao = new MyPartDao(dbp, secureRandom);
            if (user == null) {
              //this means user enrolling for the study first time
              // insert into rp_user_in_study and the history table
              dao.createUserInStudy(rpUserId, studyId);
            }
            Boolean enabled =
                dbp.get()
                    .toSelect("select enabled from rp_user_device where device_rpid=?" + " and rp_user_id=?")
                    .argString(deviceRpid[0]).argLong(rpUserId).queryBooleanOrNull();

            if (enabled == null) {
              // Add device to existing user
              dbp.get()
                  .toInsert(
                      "insert into rp_user_device (device_rpid, rp_user_id, enabled) values (?,?,?)")
                  .argString(deviceRpid[0]).argLong(rpUserId).argBoolean(true).insert(1);
            } else if (!enabled) {
              dbp.get().toUpdate(
                  "update rp_user_device set enabled=? where device_rpid=? and rp_user_id=?")
                  .argBoolean(true).argString(deviceRpid[0]).argLong(rpUserId)
                  .update(1);
            }
            //Update the sage related information in the database
            dbp.get().toInsert("insert into rp_user_sage_info (device_rpid, rp_user_id,"
                + " email,status,id,rp_study_id,createdOn) values (?,?,?,?,?,?,?)")
                .argString(deviceRpid[0])
                .argLong(rpUserId)
                .argString(email2)
                .argString(sageStatus[0])
                .argString(sageId[0])
                .argLong(studyId)
                .argDate(createdOn)
                .insert(1);

            return null;
          }, result1 -> {
            if (result1.succeeded()) {
              routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
                  .end(new JsonObject().put("device", deviceRpid[0]).encode());
            } else {
              log.error("Unable to store device registration", result1.cause());
              routingContext.response().setStatusMessage(result1.cause().getMessage())
                  .setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
            }
          });
        } else {
          JsonObject failure = new JsonObject(result.cause().getMessage());
          log.debug("The sage api returned status " + failure.getInteger("statusCode")
              + " " + failure.getString("message"));
          log.debug("Following the regular signUp process");
          dbb.transactAsync(dbp -> {
            //get the studyId from the database
            Long studyId = dbp.get().toSelect("select rp_study_id from rp_study where short_name = ?")
                .argString(study).queryLongOrNull();
            SessionKeyGenerator keyGenerator = new SessionKeyGenerator(secureRandom);
            emailToken[0] = keyGenerator.create();
            deviceRpid[0] = keyGenerator.create();
            dbp.get().toInsert("insert into rp_device_register_request (device_rpid, device_description,"
                + " email_recipient, email_token, email_create_time,rp_study_id) values (?,?,?,?,?,?)")
                .argString(deviceRpid[0])
                .argString(description)
                .argString(email)
                .argString(emailToken[0])
                .argDateNowPerDb()
                .argLong(studyId)
                .insert(1);
            // });

            // TODO check whether this email is already active and generate a different email
            //Get all the study related details.
            boolean[] sent = new boolean[1];
            JsonObject studyObj = dbp.get().toSelect(
                "select short_name,display_name,rp_study_support_email,rp_study_sponsor_name from rp_study where rp_study_id = ?")
                .argLong(studyId).<JsonObject>query(
                    (r) -> {
                      JsonObject row = null;
                      if (r.next()) {
                        row = new JsonObject();
                        row.put("short_name", r.getStringOrNull("short_name"));
                        row.put("display_name", r.getStringOrNull("display_name"));
                        row.put("rp_study_support_email", r.getStringOrNull("rp_study_support_email"));
                        row.put("rp_study_sponsor_name", r.getStringOrNull("rp_study_sponsor_name"));
                      }
                      return row;
                    });

            if (studyObj == null) {
              throw new RuntimeException("Could not find study " + study);
            }


            boolean reqEmailValidation = dbp.get().toSelect("select req_email_validation from rp_study where short_name = ?")
                .argString(study).queryBooleanOrFalse();

            log.debug("req_email_validation in registerHandler first time --->" + reqEmailValidation);


            // If this is genepool or other which does not require email check, skip the email check
            if (reqEmailValidation) {

              sent[0] = sendEmail(email, emailToken[0], studyObj.getString("short_name"),
                  studyObj.getString("rp_study_support_email"),
                  studyObj.getString("display_name"), studyObj.getString("rp_study_sponsor_name"));
              // Update the database to indicate we sent the mail
              dbp.get().toUpdate("update rp_device_register_request set email_send_time=?, email_successful=?"
                  + " where device_rpid=?")
                  .argDateNowPerDb()
                  .argBoolean(sent[0])
                  .argString(deviceRpid[0])
                  .update(1);
            } else {
              SecureRandom random = new SecureRandom();
              MyPartDao myPart = new MyPartDao(dbp, random);
              Long rpUserId = dbp.get().toSelect("select rp_user_id from rp_user_email where email_address=?")
                  .argString(email.toLowerCase()).queryLongOrNull();
              //fake the user click/verify email process, Genepool 1.1 add a new requirement to skip email link click due to participant may not have email access when consent.
              //after discuss with the group. team think the quick approach is to simulate the email link click steps by directly call verifyEmail
              Long userRpId1 = myPart.verifyEmail(email, studyId, deviceRpid[0], rpUserId);

            }

            return null;

          }, result2 -> {
            if (result2.succeeded()) {
              routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
                  .end(new JsonObject().put("device", deviceRpid[0]).encode());
            } else {
              log.error("Unable to store device registration", result2.cause());
              routingContext.response().setStatusMessage(result2.cause().getMessage())
                  .setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
            }
          });

        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> loginHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String deviceRpid = Valid.nonNull(request.getString("device"), "device required");

      if (!SessionKeyGenerator.validate(deviceRpid)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device Id is not valid");
        log.error("Device Id is not valid. DeviceId:  " + deviceRpid);
        return;
      }

      // Check whether the device is linked to a user and currently enabled
      dbb.transactAsync(dbp -> {
        // TODO rate limiting

        Long userId =
            dbp.get().toSelect("select rp_user_id from rp_user_device where device_rpid=?" + " and enabled=?")
                .argString(deviceRpid).argBoolean(true).queryLongOrNull();
        //First get studyId from deviceRpid
        Long studyId = dbp.get().toSelect("select rp_study_id from rp_device_register_request where device_rpid =?")
            .argString(deviceRpid).queryLongOrNull();
        //If studyId is null it could mean this is signUpWithSageSession and we did not create a row for that user in
        //device_registr_request.So check for deviceRpid in rp_sage_Info if found then get the studyId is cardiovascular
        if (studyId == null) {
          studyId = dbp.get().toSelect("select rp_study_id from rp_user_sage_info where device_rpid =?")
              .argString(deviceRpid).queryLongOrNull();
        }
        Long genePoolStudyId = dbp.get().toSelect("select rp_study_id from rp_study where short_name=?")
            .argString("genepool")
            .queryLongOrNull();

        if (userId != null) {
          // checking if the user is consented this is the base consent valid for cardiovascular study
          Long consentedUserId = dbp.get().toSelect("select b.rp_user_id  from rp_consent a, rp_user_device b where a.device_rpid = b.device_rpid and b.rp_user_id = ?")
              .argLong(userId).queryLongOrNull();
          // If this is genepool study make sure user has signed the genepool consent too. If the user is not consented then the consentedUserId is set to null.
          if (studyId.equals(genePoolStudyId)) {
            consentedUserId = dbp.get().toSelect("select b.rp_user_id  from rp_genepool_consent a, rp_user_device b where a.device_rpid = b.device_rpid and b.rp_user_id = ?")
                .argLong(userId).queryLongOrNull();
          }
          // User is authenticated and consented
          if (consentedUserId != null) {
            // Check if the user is still participating in the study
            Boolean participating =
                dbp.get().toSelect("select participation_status from rp_user_in_study where rp_user_id = ?")
                    .argLong(consentedUserId).queryBooleanOrFalse();

            if (participating) {
              // Get the user_rpid to set in the mh_user_profile table
              return dbp.get().toSelect("select user_rpid from rp_user_in_study where rp_user_id = ?")
                  .argLong(consentedUserId).queryLongOrNull();
            } else {
              // the user is no longer part of study, return status code 420
              return -420L;
            }

          } else {
            // User authenticated but not consented, return status code 412
            return -412L;
          }
        } else {
          log.warn("Device unknown or not allowed: " + deviceRpid);
          return -401L;
//            routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
//                .end("Device unknown or not allowed");
        }
      }, result -> {
        if (result.succeeded() && result.result() != null) {
          if (result.result() > 0) {
            routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
                .end(new JsonObject().put("authenticated", true).put("consented", true).put("dataSharing", true)
                    .put("user_rpid", result.result()).encodePrettily());
          } else {
            routingContext.response().setStatusCode((int) Math.negateExact(result.result())).end();
          }
        } else {
          log.warn("Unable to login device: " + deviceRpid, result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code()).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> resendEmailVerificationHandler(Vertx vertx) {
    return routingContext -> {

      JsonObject request = routingContext.getBodyAsJson();
      String email = Valid.nonNull(request.getString("email"), "email required");
      String deviceRpid = Valid.nonNull(request.getString("username"), "username required");

      VertxUtil.executeBlocking(vertx, future -> {
        try {
          // Find the email and the email token to resend the verification email
          dbb.transact(dbp -> {
            boolean sent = false;

            String emailToken =
                dbp.get().toSelect("select email_token from rp_device_register_request where device_rpid =?")
                    .argString(deviceRpid).queryStringOrNull();
            //First get studyId from deviceRpid
            Long studyId = dbp.get().toSelect("select rp_study_id from rp_device_register_request where device_rpid =?")
                .argString(deviceRpid).queryLongOrNull();
            //Get all the study related details.                   
            JsonObject studyObj = dbp.get().toSelect(
                "select short_name,display_name,rp_study_support_email,rp_study_sponsor_name from rp_study where rp_study_id = ?")
                .argLong(studyId).<JsonObject>query(
                    (r) -> {
                      JsonObject row = null;
                      if (r.next()) {
                        row = new JsonObject();
                        row.put("short_name", r.getStringOrNull("short_name"));
                        row.put("display_name", r.getStringOrNull("display_name"));
                        row.put("rp_study_support_email", r.getStringOrNull("rp_study_support_email"));
                        row.put("rp_study_sponsor_name", r.getStringOrNull("rp_study_sponsor_name"));
                      }
                      return row;
                    });

            if (emailToken != null) {
              sent = sendEmail(email, emailToken, studyObj.getString("short_name"),
                  studyObj.getString("rp_study_support_email"),
                  studyObj.getString("display_name"), studyObj.getString("rp_study_sponsor_name"));

              // update the database to say we send the mail
              dbp.get().toUpdate("update rp_device_register_request set email_send_time=?, email_successful=?"
                  + " where device_rpid=?").argDateNowPerDb().argBoolean(sent).argString(deviceRpid).update(1);
            }

            if (sent) {
              future.complete(deviceRpid);
            } else {
              future.fail("Couldn't send the email");
            }
          });

        } catch (Exception e) {
          future.fail(e);
        }
      }, result -> {
        if (result.succeeded()) {
          routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
              .end(new JsonObject().put("Mail sent", result.result()).encode());
        } else {
          log.error("Unable to resend email", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> dataSharingHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String scope = Valid.nonNull(request.getString("scope"), "scope required");
      String deviceRpid = Valid.nonNull(request.getString("deviceRpid"), "deviceRpid required");
      SharingScope sharingLabel = null;
      try {
        sharingLabel = SharingScope.valueOf(scope.toUpperCase());
      } catch (Exception e) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code()).end();
        return;
      }
      String label = sharingLabel.getLabel();
      // update the scope in rp_consent
      dbb.transactAsync(dbp -> {
        //Find the rpUserId for the deviceRpid, since user might be changing consent from another device
        Long rpUserId =
            dbp.get().toSelect("select rp_user_id from rp_user_device where device_rpid=?" + " and enabled=?")
                .argString(deviceRpid).argBoolean(true).queryLongOrNull();
        //find the deviceRpid in the consent table for this user
        String consentedDeviceRpid = dbp.get().toSelect("select a.device_rpid from rp_consent a, rp_user_device b where a.device_rpid = b.device_rpid and b.rp_user_id = ?")
            .argLong(rpUserId).queryStringOrNull();
        //First get all the fields of rp_consent
        Long seq = dbp.get().toSelect("select update_sequence from rp_consent where device_rpid = ? ").argString(consentedDeviceRpid)
            .queryLongOrNull();
        //first add to history table  optimistic Locking
        Long newSeq = seq + 1;
        dbp.get()
            .toInsert(
                "insert into rp_consent_history (rp_study_id,device_rpid,name,agreed_time,date_of_birth,html_consent,pdf_consent,update_sequence,data_sharing_scope,"
                    + "update_time) "
                    + "(select rp_study_id,device_rpid,name,agreed_time,date_of_birth,html_consent,pdf_consent,? as update_sequence, ?"
                    + "as data_sharing_scope, ? as  update_time  from rp_consent where device_rpid = ?)")
            .argLong(newSeq)
            .argString(scope)
            .argDateNowPerDb()
            .argString(consentedDeviceRpid)
            .insert(1);
        //update rp_consent
        dbp.get().toDelete("update rp_consent set data_sharing_scope = ?, update_time = ?, update_sequence = ?  where device_rpid = ?")
            .argString(scope).argDateNowPerDb().argLong(newSeq).argString(consentedDeviceRpid).update(1);

        return null;
      }, result -> {
        if (result.succeeded()) {
          routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
              .end(new JsonObject().put("scope changed", "successfully").encode());
        } else {
          log.error("unable to change scope", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> refreshApiTokenHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      String token = Valid.safeReq(request.getString("token"), "Value for 'token' missing or invalid");

      dbb.transactAsync(dbp -> {
        MyPartDao dao = new MyPartDao(dbp, secureRandom);

        ApiToken apiToken = dao.findApiTokenByToken(token);
        if (apiToken != null) {
          // The token was verified, create a new one
          Integer expireMinutes = config.getInteger("refresh.token.expiration.minutes", 60 * 24 * 14);
          Token tokenResult = dao.createOrReplaceApiToken(apiToken.username, apiToken.studyId, expireMinutes);
          return new JsonObject()
              .put("refresh_token", tokenResult.token)
              .put("rp_study_id", apiToken.studyId)
              .put("rp_sunet_id", apiToken.username)
              .put("rp_org_id", apiToken.orgId);
        }
        return null;
      }, result -> {
        if (result.succeeded() && result.result() != null) {
          routingContext.response().setStatusCode(HttpResponseStatus.OK.code()).end(result.result().encode());
        } else if (result.failed()) {
          log.error("Unable to generate refresh token from the given token", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        } else {
          log.error("Unable to generate refresh token from the given token (not valid or expired)");
          routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code()).end();
        }
      });
    };
  }

  //find all the participants of a study sharing data with the given researcher(sunet id)
  @NotNull
  private Handler<RoutingContext> participantsHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      Integer pg = Valid.nonNull(request.getInteger("pg"), "pg required");
      Long studyId = Valid.nonNull(request.getLong("studyId"), "studyId required");
      String sunetId = Valid.nonNull(request.getString("sunetId"), "sunetId required");
      Long sequence = request.getLong("sequence");
      String order = request.getString("order");
      Integer pageSize = config.getInteger("pagesize", 100);

      dbb.transactAsync(dbp -> {
        MyPartDao dao = new MyPartDao(dbp, secureRandom);
        // We want all the participating participants
        if (sequence == null) {
          List<MyPartDao.ParticipantInfo> participantIds =
              dao.findConsentedParticipantsForStudy(pg, studyId, sunetId, pageSize);
          return participantIds;
        } else { //We want the changed participants since
          List<MyPartDao.ParticipantInfo> participantIds =
              dao.findChangedParticipantsForStudy(pg, studyId, sunetId, pageSize, sequence, order);
          return participantIds;
        }
      }, result -> {
        if (result.succeeded()) {
          routingContext.response().setStatusCode(HttpResponseStatus.OK.code())
              .end(Json.encode(result.result()));
        } else if (result.failed()) {
          log.error("Unable to get the participants list", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> participantsShareHandler() {
    return routingContext -> {
      JsonObject request = routingContext.getBodyAsJson();
      JsonArray users = request.getJsonArray("users");
      ArrayList<ShareInfo> userL = new ArrayList<ShareInfo>();
      for (Object user : users) {
        ShareInfo info = new ShareInfo();
        info.userId = ((JsonObject) user).getLong("userId");
        userL.add(info);
      }
      Long studyId = Valid.nonNull(request.getLong("studyId"), "studyId required");
      String sunetId = Valid.nonNull(request.getString("sunetId"), "sunetId required");
      dbb.transactAsync(dbp -> {
        MyPartDao dao = new MyPartDao(dbp, secureRandom);
        List<ShareInfo> shares = dao.participantsShareFile(studyId, sunetId, userL);
        return shares;
      }, result -> {
        if (result.succeeded()) {
          routingContext.response().setStatusCode(HttpResponseStatus.OK.code())
              .end(Json.encode(result.result()));
        } else if (result.failed()) {
          log.error("Unable to find if the participant shares file", result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> withdrawHandler() {
    return routingContext -> {

      JsonObject request = routingContext.getBodyAsJson();
      String deviceRpid = Valid.nonNull(request.getString("deviceRpid"), "deviceRpid required");
      // TODO validate deviceRpid
      if (!SessionKeyGenerator.validate(deviceRpid)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device Id is not valid");
        log.error("Device Id is not valid. DeviceId:  " + deviceRpid);
        return;
      }

      dbb.transactAsync(dbp -> {
        // TODO rate limiting
        // Get the rp_user_id for the deviceRpid
        Long rpUserId =
            dbp.get().toSelect("select rp_user_id from rp_user_device where device_rpid=?" + " and enabled=?")
                .argString(deviceRpid).argBoolean(true).queryLongOrNull();
        Long studyId = dbp.get().toSelect("select rp_study_id from rp_device_register_request where device_rpid=?")
            .argString(deviceRpid).queryLongOrNull();
        //find the deviceRpid in the consent table for this user. User might have consented from another device
        JsonObject consDRpid = dbp.get().toSelect("select a.device_rpid,a.update_sequence from rp_consent a, rp_user_device b where a.device_rpid = b.device_rpid and b.rp_user_id = ?")
            .argLong(rpUserId).<JsonObject>query(r -> {
              JsonObject cons = null;
              if (r.next()) {
                cons = new JsonObject();
                cons.put("device_rpid", r.getStringOrNull());
                cons.put("update_sequence", r.getLongOrNull());
              }
              return cons;
            });
        Long genePoolStudyId = dbp.get().toSelect("select rp_study_id from rp_study where short_name=?")
            .argString("genepool")
            .queryLongOrNull();
        if (consDRpid != null && rpUserId != null) {
          Long newSeq = 0L;
          //First insert row in history table to indicate delete
          // delete from rp_genepool_consent  first to avoid fk violation
          if (studyId.equals(genePoolStudyId)) {
            Long seq = dbp.get().toSelect(
                " select update_sequence from rp_genepool_consent where device_rpid = ?")
                .argString(consDRpid.getString("device_rpid")).queryLongOrNull();
            newSeq = seq + 1;
            Sql sql = new Sql();

            log.debug("------inside withdraw before call SQL");
            sql.append(
                "insert into rp_genepool_consent_history (rp_study_id,device_rpid,race,ethnicity,zip_code,mrn,share_with_nih,treatable_genetic_findings,"
                    + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,stanford_research_registry,"
                    + "opt_out,receive_biochemical_tests,submit_urine_sample,assent_child_name,assent_adult_name,child_cannot_assent,participant_name,email_address,gender,participant_mrn,attending_physician_name,"
                    + "update_time,update_sequence,is_deleted)"
                    + "(select rp_study_id,device_rpid,race,ethnicity,zip_code,mrn,share_with_nih,treatable_genetic_findings,"
                    + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,stanford_research_registry, "
                    + "opt_out,receive_biochemical_tests,submit_urine_sample,assent_child_name,assent_adult_name,child_cannot_assent,participant_name,email_address,gender,participant_mrn,attending_physician_name"
                    + ",? as update_time,");

            sql.append(newSeq);
            sql.append(" as update_sequence, ? as is_deleted "
                + " from rp_genepool_consent where device_rpid = ?)");

            dbp.get().toInsert(sql).argDateNowPerDb().argBoolean(true).argString(consDRpid.getString("device_rpid")).insert(1);
            dbp.get().toDelete("delete from rp_genepool_consent  where device_rpid = ?")
                .argString(deviceRpid).update(1);

          }
          //insert a row in the history table to indicate the delete
          newSeq = consDRpid.getLong("update_sequence") + 1;
          Sql sql = new Sql();
          sql.append(
              "insert into rp_consent_history (rp_study_id,device_rpid,update_time,update_sequence,is_deleted,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent)"
                  + "(select rp_study_id, device_rpid, ? as update_time, ");
          sql.append(newSeq);
          sql.append(" as update_sequence, ? as is_deleted, name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent from rp_consent where device_rpid = ? )");
          dbp.get()
              .toInsert(sql).argDateNowPerDb()
              .argBoolean(true)
              .argString(consDRpid.getString("device_rpid"))
              .insert(1);
          //delete from rp_consent
          dbp.get().toDelete("delete from rp_consent  where device_rpid = ?")
              .argString(consDRpid.getString("device_rpid")).update(1);
          MyPartDao dao = new MyPartDao(dbp, secureRandom);
          // change the participation status for this user
          dao.deleteUserInStudy(rpUserId, studyId);
          return true;
        } else {
          // Could not sign out the user
          log.warn("Unable to withdraw the device " + deviceRpid);
          return false;
        }
      }, result -> {
        if (result.succeeded()) {
          if (result.result()) {
            routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code())
                .end("{\"status\":\"Withdrawn from the study.\"}");
          } else {
            routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
                .end("{\"status\":\" Not Withdrawn from the study.\"}");
          }
        } else {
          log.warn("Unable to sign out the device " + deviceRpid, result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
              .end("{\"status\":\" Not Withdrawn from the study.\"}");
        }
      });
    };
  }

  @NotNull
  private Handler<RoutingContext> consentHandler() {
    log.debug("enter consent handler  =====");
    return routingContext -> {

      log.debug("enter consent handler inside routing context");
      JsonObject request = routingContext.getBodyAsJson();
      String signingDate = LocalDateTime.now().format(FORMATTER);
      DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;
      Consent consent = new Consent();
      consent.setName(Valid.nonNull(request.getString("name"), "name required"));
      try {
        LocalDate ldate = LocalDate.parse(request.getString("birthdate"), formatter);
        Date date = Date.from(ldate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
        consent.setBirthDate(date);
      } catch (Exception e) {
        log.error("Error in date conversion");
        throw new BadRequestException("Incorrect format for birthdate. Correct format yyyy-MM-dd");
      }
      String deviceRpid = Valid.nonNull(request.getString("deviceRpid"), "deviceRpid required");
      consent.setSigningDate(signingDate);
      consent.setEmail(null);

      // TODO validate deviceRpid
      if (!SessionKeyGenerator.validate(deviceRpid)) {
        routingContext.response().setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
            .end("Device Id is not valid");
        log.error("Device Id is not valid. DeviceId:  " + deviceRpid);
        return;
      }


      dbb.transactAsync(dbp -> {
        log.debug("enter consent handler transactAsync");
        Long rpUserId = dbp.get().toSelect("select rp_user_id from rp_user_device where device_rpid = ?")
            .argString(deviceRpid).queryLongOrNull();
        log.debug("deviceRpid====" + deviceRpid);
        if (rpUserId != null) {
          String email = dbp.get()
              .toSelect("select email_address from rp_user_email where rp_user_id = ? and is_primary ='Y'")
              .argLong(rpUserId).queryStringOrNull();
          consent.setEmail(email);
        }
        log.debug("rpUserId====" + rpUserId);
        //First get studyId from deviceRpid
        Long studyId = dbp.get().toSelect("select rp_study_id from rp_device_register_request where device_rpid =?")
            .argString(deviceRpid).queryLongOrNull();
        //If studyId is null it could mean this is signUpWithSageSession and we did not create a row for that user in
        //device_register_request.So check for deviceRpid in rp_sage_Info if found then get the studyId is cardiovascular
        if (studyId == null) {
          studyId = dbp.get().toSelect("select rp_study_id from rp_user_sage_info where device_rpid =?")
              .argString(deviceRpid).queryLongOrNull();
        }

        log.debug("rp_study_id====" + studyId);
        String studyShortName = Valid.nonNull(dbp.get().toSelect("select short_name from rp_study where rp_study_id=?")
            .argLong(studyId)
            .queryStringOrNull(), "Invalid study");

        GenePoolConsent gpConsent = null;
        //if study is genepool set the scope to stanford and sponsors
        if (studyShortName.equals("genepool")) {
          consent.setScope("sponsors_and_partners");
          gpConsent = getGenePoolConsentInfo(request, routingContext);
          log.debug("getGenePoolConsentInfo new consent email address: " + gpConsent.getEmailAddress());
          createGenePoolConsent(dbp, gpConsent, consent.getEmail(), studyId, consent.getSigningDate());
          createGenePoolAssent(dbp, gpConsent, consent.getEmail(), studyId, consent.getSigningDate());
        } else {
          consent.setScope(Valid.nonNull(request.getString("scope"), "scope required"));
          createConsent(dbp, studyId, consent, studyShortName);
        }
        //We populate the base consent table for all studies
        populateBaseConsent(consent, dbp, studyId, deviceRpid);
        // Now we populate the gene pool consent table as it has foreign key pointing to the base consent
        if (studyShortName.equals("genepool")) {
          populateGenePoolConsent(gpConsent, dbp, studyId, deviceRpid);
        }
        return null;

      }, result -> {
        if (result.succeeded()) {
          // User consented
          routingContext.response().setStatusCode(HttpResponseStatus.ACCEPTED.code()).end();
        } else {
          log.warn("Unable to login device: " + deviceRpid, result.cause());
          routingContext.response().setStatusCode(HttpResponseStatus.UNAUTHORIZED.code()).end();
        }
      });


    };
  }

  private GenePoolConsent getGenePoolConsentInfo(JsonObject request, RoutingContext routingContext) {

    GenePoolConsent gpConsent = new GenePoolConsent();
    if (request.getBoolean("adult_participant") != null) {
      gpConsent.setAdultParticipant(request.getBoolean("adult_participant"));
    }
    if (request.getBoolean("opt_out") != null) {
      gpConsent.setOptOut(request.getBoolean("opt_out"));
    }
    if (request.getBoolean("both_genetic_findings") != null) {
      gpConsent.setBothGeneticFindings(request.getBoolean("both_genetic_findings"));
    }
    if (request.getBoolean("do_not_inform_genetic_findings") != null) {
      gpConsent.setDoNotInformGeneticFindings(request.getBoolean("do_not_inform_genetic_findings"));
    }

    if (request.getString("family_history_of_disease") != null) {
      Valid.alphaSpaceMaxLength(request.getString("family_history_of_disease"), 256, "Invalid Disease Name");
      gpConsent.setFamilyHistoryOfDisease(request.getString("family_history_of_disease"));
    }
    if (request.getBoolean("related_to_family_history") != null) {
      gpConsent.setRelatedToFamilyHistory(request.getBoolean("related_to_family_history"));
    }
    if (request.getBoolean("share_with_nih") != null) {
      gpConsent.setShareWithNih(request.getBoolean("share_with_nih"));
    }
    if (request.getBoolean("treatable_genetic_findings") != null) {
      gpConsent.setTreatableGeneticFindings(request.getBoolean("treatable_genetic_findings"));
    }
    if (request.getBoolean("stanford_research_registry") != null) {
      gpConsent.setStanfordResearchRegistry(request.getBoolean("stanford_research_registry"));
    }
    if (request.getInteger("zip_code") != null) {
      gpConsent.setZipCode(request.getInteger("zip_code"));
    }
    if (request.getString("ethnicity") != null) {
      gpConsent.setEthnicity(request.getString("ethnicity"));
    }
    if (request.getString("race") != null) {
      gpConsent.setRace(request.getString("race"));
    }

    //newly add fields
    if (request.getBoolean("receive_biochemical_tests") != null) {
      gpConsent.setReceiveBiochemicalTests(request.getBoolean("receive_biochemical_tests"));
    }
    if (request.getBoolean("submit_urine_sample") != null) {
      gpConsent.setSubmitUrineSample(request.getBoolean("submit_urine_sample"));
    }
    if (request.getBoolean("child_cannot_assent") != null) {
      gpConsent.setChildCannotAssent(request.getBoolean("child_cannot_assent"));
    }
    //Due to assent_child_name is optional, we should skip the following logic if it is null. in the Valid method, it throw exception if it is null which
    //assume it is required.
    if (request.getString("assent_child_name") != null) {
      String assentChildName = request.getString("assent_child_name");
      Valid.alphaSpaceMaxLength(assentChildName, 256, "Invalid assent child name Name");
      gpConsent.setAssentChildName(assentChildName);
    }

    String assentAdultName = request.getString("assent_adult_name");
    if (assentAdultName != null) {
      Valid.alphaSpaceMaxLength(assentAdultName, 256, "Invalid assent_adult_name Name");
      gpConsent.setAssentAdultName(assentAdultName);
    }

    String gender = request.getString("gender");
    if (gender != null) {
      Valid.alphaSpaceMaxLength(gender, 256, "Invalid gender");
      gpConsent.setGender(gender);
    }

    if (request.getString("email_address") != null) {
      //gpConsent.setEmailAddress(Valid.nonNull(request.getString("email_address"), "email_address required "));
      gpConsent.setEmailAddress(request.getString("email_address"));
    }
    Valid.alphaSpaceMaxLength(request.getString("name"), 256, "Invalid Name");

    String participantName = request.getString("participant_name");
    Valid.alphaSpaceMaxLength(participantName, 256, "Invalid participant_name");
    gpConsent.setParticipantName(Valid.nonNull(participantName, "participant_name required"));

    gpConsent.setParticipantMrn(Valid.nonNull(request.getString("participant_mrn"), "participant_mrn required"));

    if (request.getString("attending_physician_name") != null) {
      //gpConsent.setAttendingPhysicianName(Valid.nonNull(request.getString("attending_physician_name"), "attending_physician_name required"));
      gpConsent.setAttendingPhysicianName(request.getString("attending_physician_name"));
    }

    return gpConsent;
  }

  private void populateBaseConsent(Consent consent, Supplier<Database> dbp, Long studyId, String deviceRpid) {
    //here you insert both into the rp_consent and rp_consent_history table
    dbp.get()
        .toInsert(
            "insert into rp_consent (rp_study_id,device_rpid,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent,update_time,update_sequence) values(?,?,?,?,?,?,?,?,?,0)")
        .argLong(studyId).argString(deviceRpid).argString(consent.getName()).argDateNowPerDb().argDate(consent
        .getBirthDate())
        .argString(consent.getScope()).argString(consent.getHtmlConsent())
        .argBlobBytes(consent.getPdfConsent())
        .argDateNowPerDb()
        .insert(1);
    // Now add it to the history table
    dbp.get()
        .toInsert("insert into rp_consent_history (rp_study_id,device_rpid,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent,update_time,update_sequence) values(?,?,?,?,?,?,?,?,?,0)")
        .argLong(studyId).argString(deviceRpid).argString(consent.getName()).argDateNowPerDb().argDate(consent
        .getBirthDate())
        .argString(consent.getScope()).argString(consent.getHtmlConsent())
        .argBlobBytes(consent.getPdfConsent())
        .argDateNowPerDb()
        .insert(1);

  }

  private void populateGenePoolConsent(GenePoolConsent gpConsent, Supplier<Database> dbp, Long studyId, String deviceRpid) {
    // Add it to the rp_genepool_consent

    dbp.get().toInsert(
        "insert into rp_genepool_consent (rp_study_id,device_rpid,race,ethnicity,zip_code,share_with_nih,treatable_genetic_findings,"
            + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,stanford_research_registry,"
            + "adult_participant,opt_out,receive_biochemical_tests,submit_urine_sample,assent_child_name,assent_adult_name,child_cannot_assent,participant_name,email_address,gender,participant_mrn,attending_physician_name,html_assent, pdf_assent, update_time,update_sequence) values ("
            + "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)").argLong(studyId).argString(deviceRpid)
        .argString(gpConsent.getRace()).argString(gpConsent.getEthnicity()).argInteger(gpConsent.getZipCode())
        .argBoolean(gpConsent.getShareWithNih()).argBoolean(gpConsent.getTreatableGeneticFindings()).argBoolean(gpConsent.getDoNotInformGeneticFindings())
        .argBoolean(gpConsent.getRelatedToFamilyHistory()).argBoolean(gpConsent.getBothGeneticFindings()).argString(gpConsent.getFamilyHistoryOfDisease())
        .argBoolean(gpConsent.getStanfordResearchRegistry())
        .argBoolean(gpConsent.getIsAdultParticipant())
        .argBoolean(gpConsent.getOptOut())
        .argBoolean(gpConsent.getReceiveBiochemicalTests()).argBoolean(gpConsent.getSubmitUrineSample()).argString(gpConsent.getAssentChildName()).argString(gpConsent.getAssentAdultName()).argBoolean(gpConsent.getChildCannotAssent()).argString(gpConsent.getParticipantName())
        .argString(gpConsent.getEmailAddress()).argString(gpConsent.getGender()).argString(gpConsent.getParticipantMrn()).argString(gpConsent.getAttendingPhysicianName())
        .argClobString(gpConsent.getHtmlAssent())
        .argBlobBytes(gpConsent.getPdfAssent())
        .argDateNowPerDb().insert(1);


    dbp.get().toInsert(
        "insert into rp_genepool_consent_history (rp_study_id,device_rpid,race,ethnicity,zip_code,share_with_nih,treatable_genetic_findings,"
            + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,stanford_research_registry,"
            + "adult_participant,opt_out,receive_biochemical_tests,submit_urine_sample,assent_child_name,assent_adult_name,child_cannot_assent,participant_name,email_address,gender,participant_mrn,attending_physician_name,html_assent, pdf_assent,update_time,update_sequence) values ("
            + "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)").argLong(studyId).argString(deviceRpid)
        .argString(gpConsent.getRace()).argString(gpConsent.getEthnicity()).argInteger(gpConsent.getZipCode())
        .argBoolean(gpConsent.getShareWithNih()).argBoolean(gpConsent.getTreatableGeneticFindings()).argBoolean(gpConsent.getDoNotInformGeneticFindings())
        .argBoolean(gpConsent.getRelatedToFamilyHistory()).argBoolean(gpConsent.getBothGeneticFindings()).argString(gpConsent.getFamilyHistoryOfDisease())
        .argBoolean(gpConsent.getStanfordResearchRegistry())
        .argBoolean(gpConsent.getIsAdultParticipant())
        .argBoolean(gpConsent.getOptOut())
        .argBoolean(gpConsent.getReceiveBiochemicalTests()).argBoolean(gpConsent.getSubmitUrineSample()).argString(gpConsent.getAssentChildName()).argString(gpConsent.getAssentAdultName()).argBoolean(gpConsent.getChildCannotAssent()).argString(gpConsent.getParticipantName())
        .argString(gpConsent.getEmailAddress()).argString(gpConsent.getGender()).argString(gpConsent.getParticipantMrn()).argString(gpConsent.getAttendingPhysicianName())
        .argClobString(gpConsent.getHtmlAssent())
        .argBlobBytes(gpConsent.getPdfAssent())
        .argDateNowPerDb().insert(1);
    //update the  rp_consent and rp_consent_history table to reflect this change
    Long seq = dbp.get().toSelect("select update_sequence from rp_consent  where device_rpid = ?").argString(deviceRpid).queryLongOrNull();
    Long newSeq = seq + 1;
    //Also update the html and pdf consent in rp_consent
    dbp.get().toUpdate("update rp_consent set html_consent = ?, pdf_consent = ? , update_time = ? , update_sequence = ? where device_rpid = ?").argClobString(gpConsent.getHtmlConsent())
        .argBlobBytes(gpConsent.getPdfConsent()).argDateNowPerDb().argLong(newSeq).argString(deviceRpid).update(1);
    dbp.get()
        .toInsert(
            "insert into rp_consent_history (update_sequence,rp_study_id,device_rpid,name,agreed_time,date_of_birth,html_consent,pdf_consent,data_sharing_scope,"
                + "update_time)(select update_sequence,rp_study_id,device_rpid,name,agreed_time,date_of_birth, html_consent,pdf_consent,"
                + "data_sharing_scope, ? as  update_time  from rp_consent where device_rpid = ?)")
        .argDateNowPerDb()
        .argString(deviceRpid)
        .insert(1);
  }

  private void createGenePoolAssent(Supplier<Database> dbp, GenePoolConsent consent, String email, Long rpStudyId, String signingDate) throws Exception {
    InputStream inS = Thread.currentThread().getContextClassLoader().getResourceAsStream("genepool/assentAgreement.html");
    Scanner scn = new Scanner(inS);
    String consentFull = scn.useDelimiter("\\Z").next();
    scn.close();

    HashMap<String, String> map = new HashMap<>();
    //put the adult name and current date in map
    map.put("assent.child.name", consent.getAssentChildName());
    map.put("assent.child.date", signingDate);

    String completeHtmlAssent = Util.resolveHtmlTemplate(consentFull, map);
    final byte[] pdfBytes = createPdfDoc(completeHtmlAssent);
    consent.setHtmlAssent(completeHtmlAssent);
    consent.setPdfAssent(pdfBytes);

    //get study details
    JsonObject studyObj = dbp.get().toSelect(
        "select rp_study_support_email,rp_study_email_subject from rp_study where rp_study_id = ?")
        .argLong(rpStudyId).<JsonObject>query(
            (r) -> {
              JsonObject row = null;
              if (r.next()) {
                row = new JsonObject();
                row.put("rp_study_support_email", r.getStringOrNull("rp_study_support_email"));
                row.put("rp_study_email_subject", r.getStringOrNull("rp_study_email_subject"));
              }
              return row;
            });
    mailer.sendAttachment(studyObj.getString("rp_study_support_email"), null, email, null, null,
        ASSENT_EMAIL_SUBJECT, completeHtmlAssent, pdfBytes);
  }
}
