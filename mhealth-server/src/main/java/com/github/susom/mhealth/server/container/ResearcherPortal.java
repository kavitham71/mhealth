package com.github.susom.mhealth.server.container;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.services.DynamicSqlReportGenerator;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.Token;
import com.github.susom.vertx.base.AuthenticatedUser;
import com.github.susom.vertx.base.Security;
import com.github.susom.vertx.base.StrictBodyHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.vertx.base.VertxBase;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.susom.vertx.base.VertxBase.sendJson;

/**
 * Portal for researchers at Stanford/Oxford. This should allow them to
 * to authenticate themselves and view the list of studies available 
 * then obtain a api token which needs to be exchanged for an access
 * token required to access the api's for that study
 * @author ritikam
 */
public class ResearcherPortal {
  private static final Logger log = LoggerFactory.getLogger(ResearcherPortal.class);
  private final Builder dbb;
  private final SecureRandom secureRandom;
  private final Config config;
  private final Map<String, @Untainted String> fileToSql;
  private final Security security;

  public ResearcherPortal(Builder dbb, SecureRandom secureRandom, Config config, Security security, Map<String, @Untainted String> fileToSql) {
    this.dbb = dbb;
    this.secureRandom = secureRandom;
    this.config = config;
    this.security = security;
    this.fileToSql = fileToSql;
  }

  public Router router(Vertx vertx) {
    return addToRouter(vertx, Router.router(vertx));
  }

  public Router addToRouter(Vertx vertx, Router router) {
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    router.route().handler(security.requireAuthority("med-research-it:mhealth")).failureHandler(VertxBase::jsonApiFail);

    router.post("/api/v1/studies").handler(smallBodyHandler);
    router.post("/api/v1/studies").handler(this::studies).failureHandler(VertxBase::jsonApiFail);

    router.route("/api/v1/token/*").handler(security.requireAuthority("med-research-it:mhealth-api")).failureHandler(VertxBase::jsonApiFail);
    router.post("/api/v1/token/issue").handler(smallBodyHandler);
    router.post("/api/v1/token/issue").handler(this::generateApiToken).failureHandler(VertxBase::jsonApiFail);

    router.route("/api/v1/genepool/*").handler(security.requireAuthority("med-research-it:mhealth-genepool")).failureHandler(VertxBase::jsonApiFail);
    router.post("/api/v1/genepool/participants").handler(smallBodyHandler);
    router.post("/api/v1/genepool/participants").handler(this::genePoolParticipants).failureHandler(VertxBase::jsonApiFail);

    router.post("/api/v1/genepool/status/update").handler(smallBodyHandler);
    router.post("/api/v1/genepool/status/update").handler(this::updateGenePoolStatus).failureHandler(VertxBase::jsonApiFail);

    // TODO commenting for now because they aren't using the rp_ tables and they are
    // not scoped to the study (should probably be /api/v1/genepool/reports etc.)
    //router.get("/api/v1/getReports").handler(this::getReports).failureHandler(VertxBase::jsonApiFail);
   //router.get("/api/v1/getReport/:sql").handler(this::getReport).failureHandler(VertxBase::jsonApiFail);

    router.get("/*").handler(new com.github.susom.vertx.base.StrictResourceHandler(vertx)
        .addDir("static/researcher-portal")
        .addDir("static/assets", "**/*", "assets")
        .rootIndex("index.nocache.html"));

    return router;
  }

  private void studies(RoutingContext rc) {
    dbb.transactAsync(dbp -> {
      MyPartDao dao = new MyPartDao(dbp, secureRandom);
      JsonObject request = rc.getBodyAsJson();
      String sunetId = AuthenticatedUser.from(rc).getAuthenticatedAs();
      Integer pg = 1;
      if (request.containsKey("pg")) {
        pg = request.getInteger("pg");
      }
      Integer pageSize = config.getInteger("pagesize", 100);
      List<MyPartDao.Study> studies = dao.getStudies(pageSize, pg, sunetId);
      Boolean admin = dao.verifyGenePoolAdmin(sunetId);
      // Check if we have next page
      boolean nextPage = (studies.size() > pageSize);
      // construct the result json
      JsonObject scoperResult = new JsonObject();
      JsonObject meta = new JsonObject();
      meta.put("currentPage", pg);
      meta.put("nextPage", nextPage);
      meta.put("pageSize", pageSize);
      scoperResult.put("meta", meta);
      scoperResult.put("genePoolAdmin",admin);
      if (nextPage) {
        scoperResult.put("studies", studies.subList(0, studies.size() - 1));
      } else {
        scoperResult.put("studies", studies);
      }
      scoperResult.put("action","success");
      return scoperResult;
    } , sendJson(rc));
  }

  private void getReport( RoutingContext rc) {
    dbb.transactAsync(dbp -> {
          String html;
          String sqlFile = rc.request().getParam("sql");
          @Untainted String sql = fileToSql.get(sqlFile);
          DynamicSqlReportGenerator report = new DynamicSqlReportGenerator(sqlFile,sql,dbp);
          html = report.execute();
          rc.response().putHeader("content-type", "text/html").end(html);
          return null;
        }, result -> {
          if (result.failed()) {
            rc.fail(result.cause());
          }
    });
}

  private void getReports(RoutingContext rc) {
    JsonObject result = new JsonObject();
    result.put("action","success");
    List<String> files = new ArrayList<>(this.fileToSql.keySet());
    result.put("files",files);
    rc.response().putHeader("content-type", "application/json").end(result.encode());
  }

  private void genePoolParticipants(RoutingContext rc) {
    dbb.transactAsync(dbp -> {
      MyPartDao dao = new MyPartDao(dbp, secureRandom);
      Integer pg = 1;
      Integer pageSize = config.getInteger("pagesize", 100);
      JsonObject request = rc.getBodyAsJson();
      if (request.containsKey("pg")) {
        pg = request.getInteger("pg");
      }
      if (request.containsKey("pageSize")) {
        pageSize = request.getInteger("pageSize");
      }
      List<MyPartDao.GenePoolParticipant> participants = dao.genePoolParticipants(pg,pageSize);
      // Check if we have next page
      boolean nextPage = (participants.size() > pageSize);
      //JsonArray jArray = new JsonArray(participants);
      JsonObject result = new JsonObject();
      if (nextPage) {
        result.put("participants", participants.subList(0, participants.size() - 1));
      } else {
        result.put("participants", participants);
      }
      result.put("action","success");
      result.put("nextPage", nextPage);
      return result;
    } , sendJson(rc));
  }

  private void updateGenePoolStatus(RoutingContext rc) {
    dbb.transactAsync(dbp -> {
      MyPartDao dao = new MyPartDao(dbp, secureRandom);
      Long userId = 0L;
      String status = null;
      JsonObject request = rc.getBodyAsJson();
      if (request.containsKey("userId")) {
        userId = request.getLong("userId");
      }
      if (request.containsKey("status")) {
        status = request.getString("status");
      }
      Valid.isTrue((status.equals("ordered") || status.equals("completed")),"invalid status");
      dao.updateGenePoolStatus(userId,status);
      JsonObject result = new JsonObject();
      result.put("action","success");
      return result;
    } , sendJson(rc));
  }

  private void generateApiToken(RoutingContext rc) {

    JsonObject jsnObj = rc.getBodyAsJson();
    String sunetId = AuthenticatedUser.from(rc).getAuthenticatedAs();
    Long studyId = Valid.nonNull(jsnObj.getLong("studyId"),"studyId cannot be null");

    //check whether the token already exists for sunetId
    dbb.transactAsync(dbp -> {
      MyPartDao dao = new MyPartDao(dbp, secureRandom);
      //Check if the researcher has access to study
      Long validId = dbp.get().toSelect("select rp_study_id from rp_researcher_data_access  where rp_sunet_id = ? and rp_study_id = ? ")
          .argString(sunetId).argLong(studyId).queryLongOrNull();
      Valid.nonNull(validId,"Researcher does not have access to the study");
      Integer expireMinutes = config.getInteger("api.token.expiration.minutes", 60);
      Token tokenResult = dao.createOrReplaceApiToken(sunetId, studyId, expireMinutes);
      JsonObject result = new JsonObject();
      result.put("action","success");
      result.put("token", tokenResult.token);
      result.put("validTo",tokenResult.validTo.toString());
      return result;
    } , sendJson(rc));
  }
}
