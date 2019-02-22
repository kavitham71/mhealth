package com.github.susom.mhealth.server.services;

import com.github.susom.database.Database;
import com.github.susom.database.Sql;
import io.vertx.core.json.JsonObject;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/**
 * Database operations for the research participant portal (the rp_* tables).
 *
 * @author garricko
 */
public class MyPartDao {
  private final Supplier<Database> dbs;
  private final SecureRandom secureRandom;

  public MyPartDao(Supplier<Database> dbs, SecureRandom secureRandom) {
    this.dbs = dbs;
    this.secureRandom = secureRandom;
  }

  public String registerDevice(String deviceRpid, String email, String emailToken, String description, Long studyId) {
    if (deviceRpid == null ) {
      SessionKeyGenerator keyGenerator = new SessionKeyGenerator(secureRandom);
      deviceRpid = keyGenerator.create();
    }
    dbs.get().toInsert("insert into rp_device_register_request (device_rpid, device_description,"
        + " email_recipient, email_token, email_create_time,rp_study_id, email_send_time, email_successful) values (?,?,?,?,?,?,?,?)")
        .argString(deviceRpid)
        .argString(description)
        .argString(email)
        .argString(emailToken)
        .argDateNowPerDb()
        .argLong(studyId)
        .argDateNowPerDb()
        .argBoolean(true)
        .insert(1);
        return deviceRpid;
  }

  public void deleteUserInStudy(Long rpUserId,Long studyId) {
    //First get the updateSequence from rp_user_in_study
    User user = dbs.get().toSelect("select update_sequence, user_rpid from rp_user_in_study where  rp_user_id = ? and rp_study_id = ?")
        .argLong(rpUserId).argLong(studyId).<User>query(r -> {
          User row = null;
          if (r.next()) {
            row = new User();
            row.updateSeq = r.getLongOrNull("update_sequence");
            row.userRpid = r.getLongOrNull("user_rpid");
          }
          return row;
        });
    //First make the insert in history table optimistic locking stratergy
    dbs.get()
        .toInsert(
            "insert into rp_user_in_study_history(rp_user_id,rp_study_id,user_rpid,participation_status,update_sequence,update_time,is_deleted) values(?,?,?,?,?,?,?)")
        .argLong(rpUserId).argLong(studyId).argLong(user.userRpid)
        .argBoolean(false).argLong((user.updateSeq) + 1).argDateNowPerDb().argBoolean(true).insert(1);
    //delete row from rp_user_in_study
    dbs.get().toDelete("delete from rp_user_in_study where user_rpid = ? and rp_study_id = ?")
        .argLong(user.userRpid).argLong(studyId).update(1);
  }

  public void createUserInStudy(Long rpUserId, Long studyId) {
    Long userRpid = dbs.get()
        .toInsert(
            "insert into rp_user_in_study(rp_user_id,rp_study_id,user_rpid,participation_status,enrollment_time,update_time,update_sequence) values(?,?,?,?,?,?,0)")
        .argLong(rpUserId).argLong(studyId).argPkSeq("rp_pk_seq")
        .argBoolean(true).argDateNowPerDb().argDateNowPerDb().insertReturningPkSeq("user_rpid");
    dbs.get()
        .toInsert(
            "insert into rp_user_in_study_history(rp_user_id,rp_study_id,user_rpid,participation_status,enrollment_time,update_time,update_sequence) values(?,?,?,?,?,?,0)")
        .argLong(rpUserId).argLong(studyId).argLong(userRpid)
        .argBoolean(true).argDateNowPerDb().argDateNowPerDb().insert(1);
  }

  public void createBaseConsent(Long studyId, String deviceRpid,String name, Date birthdate, String scope,String htmlConsent,byte[] pdfConsent, Long updateSequence ) {
    dbs.get()
        .toInsert(
            "insert into rp_consent (rp_study_id,device_rpid,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent,update_time,update_sequence) values(?,?,?,?,?,?,?,?,?,?)")
        .argLong(studyId).argString(deviceRpid).argString(name).argDateNowPerDb().argDate(birthdate)
        .argString(scope).argString(htmlConsent)
        .argBlobBytes(pdfConsent)
        .argDateNowPerDb().argLong(updateSequence)
        .insert(1);
    // Now add it to the history table
    dbs.get()
        .toInsert("insert into rp_consent_history (rp_study_id,device_rpid,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent,update_time,update_sequence) values(?,?,?,?,?,?,?,?,?,?)")
        .argLong(studyId).argString(deviceRpid).argString(name).argDateNowPerDb().argDate(birthdate)
        .argString(scope).argString(htmlConsent)
        .argBlobBytes(pdfConsent)
        .argDateNowPerDb().argLong(updateSequence)
        .insert(1);

  }

  public void createGenePoolConsent(String childName,String race, String ethnicity, Integer zipCode,String mrn,Supplier<Database> dbp,Long studyId, String deviceRpid,
                                    Boolean shareWithNih, Boolean treatableGeneticFindings, Boolean doNotInformGeneticFindings,
                                    Boolean relatedToFamilyHistory, Boolean bothGeneticFindings, String familyHistoryOfDisease,
                                    Boolean wearDevice, Boolean stanfordRegistry) {
    // Add it to the rp_genepool_consent
    dbp.get().toInsert(
        "insert into rp_genepool_consent (rp_study_id,device_rpid,child_name,race,ethnicity,zip_code,mrn,share_with_nih,treatable_genetic_findings,"
            + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,wear_device,stanford_research_registry,update_time,update_sequence) values ("
            + "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)").argLong(studyId).argString(deviceRpid).argString(childName)
        .argString(race).argString(ethnicity).argInteger(zipCode).argString(mrn)
        .argBoolean(shareWithNih).argBoolean(treatableGeneticFindings).argBoolean(doNotInformGeneticFindings)
        .argBoolean(relatedToFamilyHistory).argBoolean(bothGeneticFindings).argString(familyHistoryOfDisease)
        .argBoolean(wearDevice).argBoolean(stanfordRegistry).argDateNowPerDb().insert(1);
    dbp.get().toInsert(
        "insert into rp_genepool_consent_history (rp_study_id,device_rpid,child_name,race,ethnicity,zip_code,mrn,share_with_nih,treatable_genetic_findings,"
            + "do_not_inform_genetic_findings,related_to_family_history, both_genetic_findings,family_history_of_disease,wear_device,stanford_research_registry,update_time,update_sequence) values ("
            + "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)").argLong(studyId).argString(deviceRpid).argString(childName)
        .argString(race).argString(ethnicity).argInteger(zipCode).argString(mrn)
        .argBoolean(shareWithNih).argBoolean(treatableGeneticFindings).argBoolean(doNotInformGeneticFindings)
        .argBoolean(relatedToFamilyHistory).argBoolean(bothGeneticFindings).argString(familyHistoryOfDisease)
        .argBoolean(wearDevice).argBoolean(stanfordRegistry).argDateNowPerDb().insert(1);

  }

  public Long verifyEmail(String email, Long studyId, String deviceRpid, Long userRpid) {

     Long userId = dbs.get().toInsert("insert into rp_user (rp_user_id) values (?)").argPkSeq("rp_pk_seq")
          .insertReturningPkSeq("rp_user_id");

    dbs.get()
        .toInsert("insert into rp_user_email (rp_user_email_id, rp_user_id, email_address,"
            + " is_primary, verify_complete_time) values (?,?,?,?,?)")
        .argPkSeq("rp_pk_seq").argLong(userId).argString(email).argBoolean(true).argDateNowPerDb()
        .insert(1);
    if (userRpid == null) {
       createUserInStudy(userId,studyId);
    } else {
      dbs.get()
          .toInsert(
              "insert into rp_user_in_study(rp_user_id,rp_study_id,user_rpid,participation_status,enrollment_time,update_time,update_sequence) values(?,?,?,?,?,?,0)")
          .argLong(userId).argLong(studyId).argLong(userRpid)
          .argBoolean(true).argDateNowPerDb().argDateNowPerDb().insert(1);
      dbs.get()
          .toInsert(
              "insert into rp_user_in_study_history(rp_user_id,rp_study_id,user_rpid,participation_status,enrollment_time,update_time,update_sequence) values(?,?,?,?,?,?,0)")
          .argLong(userId).argLong(studyId).argLong(userRpid)
          .argBoolean(true).argDateNowPerDb().argDateNowPerDb().insert(1);

    }

    dbs.get().toInsert("insert into rp_user_device (device_rpid, rp_user_id, enabled) values (?,?,?)")
        .argString(deviceRpid).argLong(userId).argBoolean(true).insert(1);
    return userRpid;
  }

  public Client clientByClientId(String clientId) {
    return dbs.get().toSelect("select client_secret, redirect_uri from rp_study_app where client_id=?")
        .argString(clientId).queryOneOrNull(r -> {
          Client client = new Client();
          client.clientId = clientId;
          client.clientSecret = r.getStringOrNull();
          client.redirectUri = r.getStringOrNull();
          return client;
        });
  }

  public Long findOrCreateUserIdByEmail(String email) {
    Long userId = dbs.get().toSelect("select rp_user_id from rp_user_email where email_address=?")
        .argString(email).queryLongOrNull();

    if (userId == null) {
      // Create a new user
      userId = dbs.get().toInsert("insert into rp_user (rp_user_id) values (?)")
          .argPkSeq("rp_pk_seq")
          .insertReturningPkSeq("rp_user_id");

      dbs.get().toInsert("insert into rp_user_email (rp_user_email_id, rp_user_id, email_address,"
          + " is_primary, verify_complete_time) values (?,?,?,?,?)")
          .argPkSeq("rp_pk_seq")
          .argLong(userId)
          .argString(email)
          .argBoolean(true)
          .argDateNowPerDb()
          .insert(1);
    }

    return userId;
  }

  public List<Study> getStudies(Integer pageSize, Integer pg, String sunetId) {
    Integer fetchSize = pageSize + 1;
    Integer offset = ((pg - 1) * pageSize);
    return dbs.get().toSelect(
            "select a.rp_study_id, b.short_name, b.display_name from rp_researcher_data_access a , rp_study b where rp_sunet_id = ? and a.rp_study_id = b.rp_study_id  order by a.rp_study_id asc offset (?) rows fetch first (?) rows only")
            .argString(sunetId).argInteger(offset).argInteger(fetchSize).queryMany((r) -> {
              Study study = new Study();
              study.studyId = r.getLongOrZero();
              study.shortName = r.getStringOrEmpty();
              study.displayName = r.getStringOrEmpty();
          return study;
        });
  }


  // check whether user shares the file with the given researcher
  public List<ShareInfo> participantsShareFile(Long studyId, String sunetId, List<ShareInfo> users) {
    for (ShareInfo user : users) {
      String selectClause = "select 'Y' from rp_user_in_study a, rp_user_device b, rp_consent c where";
      String whereClause = " a.rp_study_id = ? and a.participation_status = ? and a.user_rpid = ? and a.rp_user_id = b.rp_user_id and b.device_rpid = c.device_rpid and ";
      Boolean share = null;
      String dataSharScope =
          dbs.get().toSelect("select rp_data_sharing_scope from rp_researcher_data_access where rp_study_id = ? and"
              + " rp_sunet_id = ? ").argLong(studyId).argString(sunetId).queryStringOrNull();
      if (dataSharScope.equals("all_qualified_researchers")) {
        Sql sql1 = new Sql();
        sql1.append(selectClause);
        sql1.append(whereClause);
        sql1.append("c.data_sharing_scope = 'all_qualified_researchers' ");
        share =
            dbs.get().toSelect(sql1)
                .argLong(studyId).argBoolean(true).argLong(user.userId).queryBooleanOrFalse();

      } else if (dataSharScope.equals("sponsors_and_partners")) {
        Sql sql2 = new Sql();
        sql2.append("select 'Y' from rp_user_in_study a, rp_user_device b, rp_consent c where ");
        sql2.append(" ( " + whereClause);
        sql2.append("c.data_sharing_scope = 'sponsors_and_partners' )");
        sql2.append(" or ( " + whereClause);
        sql2.append("c.data_sharing_scope = 'all_qualified_researchers' )");
        share =
            dbs.get().toSelect(sql2)
                .argLong(studyId).argBoolean(true).argLong(user.userId).argLong(studyId).argBoolean(true)
                .argLong(user.userId).queryBooleanOrFalse();
      }
      user.shares = share;
    }
    ;
    return users;
  }

  //find all the  changed participants of a study sharing data with the given researcher(sunet id) since the given
  // sequence number
  public List<ParticipantInfo> findChangedParticipantsForStudy(Integer pg, Long studyId, String sunetId,
                                                                 Integer pageSize, Long sequence, String order) {
    List<ParticipantInfo> userIds = new ArrayList<ParticipantInfo>();
    Integer fetchSize = pageSize + 1;
    Integer offset = ((pg - 1) * pageSize);
    //Get the scope clause based on sunetId and studyId and construct the sql
    Sql sql = new Sql();
    String orderClause = null;
    if (order.equals("desc")) {
      orderClause = " desc ";
    } else {
      orderClause = " asc ";
    }
    String whereClause = " a.rp_study_id = ? and a.participation_status = ? "
        + " and a.rp_user_id = b.rp_user_id and b.device_rpid = c.device_rpid and c.update_sequence > ? and ";
    String endClause1 = " order by c.update_sequence ";
    String  endClause2 =  " offset (?) rows fetch first (?) rows only ";
    sql = sql.append("select distinct a.user_rpid, c.update_sequence from rp_user_in_study a, rp_user_device b, rp_consent c where ");
    String dataSharScope =
        dbs.get().toSelect("select rp_data_sharing_scope from rp_researcher_data_access where rp_study_id = ? and "
            + " rp_sunet_id = ? ").argLong(studyId).argString(sunetId).queryStringOrNull();
    if (dataSharScope.equals("all_qualified_researchers")) {
      sql = sql.append(whereClause);
      sql = sql.append("c.data_sharing_scope = 'all_qualified_researchers' ");
      sql = sql.append(endClause1);
      sql = sql.append(orderClause);
      sql = sql.append(endClause2);
      userIds =
          dbs.get().toSelect(sql)
              .argLong(studyId).argBoolean(true)
              .argLong(sequence).argInteger(offset).argInteger(fetchSize)
              .<ParticipantInfo>queryMany((r) -> {
                ParticipantInfo info = new ParticipantInfo();
                info.id = r.getLongOrNull();
                info.sequence = r.getLongOrNull();
                //info.name = r.getStringOrNull();
                return info;
              });
    } else if (dataSharScope.equals("sponsors_and_partners")) {
      sql = sql.append("(" + whereClause);
      sql = sql.append("c.data_sharing_scope = 'sponsors_and_partners' " + ")");
      sql = sql.append(" or (" + whereClause);
      sql = sql.append("c.data_sharing_scope = 'all_qualified_researchers'" + ")");
      sql = sql.append(endClause1);
      sql = sql.append(orderClause);
      sql = sql.append(endClause2);
      userIds =
          dbs.get().toSelect(sql)
              .argLong(studyId).argBoolean(true).argLong(sequence).argLong(studyId).argBoolean(true)
              .argLong(sequence).argInteger(offset).argInteger(fetchSize)
              .<ParticipantInfo>queryMany((r) -> {
                ParticipantInfo info = new ParticipantInfo();
                info.id = r.getLongOrNull();
                info.sequence = r.getLongOrNull();
               // info.name = r.getStringOrNull();
                return info;
              });
    }
    return userIds;
  }



  //find all the participants of a study sharing data with the given researcher(sunet id)
  public List<ParticipantInfo> findConsentedParticipantsForStudy(Integer pg, Long studyId, String sunetId,
                                                                 Integer pageSize) {
    List<ParticipantInfo> userIds = new ArrayList<ParticipantInfo>();
    Integer fetchSize = pageSize + 1;
    Integer offset = ((pg - 1) * pageSize);
    //Get the scope clause based on sunetId and studyId and construct the sql
    Sql sql = new Sql();
    String whereClause = " a.rp_study_id = ? and a.participation_status = ? "
        + " and a.rp_user_id = b.rp_user_id and b.device_rpid = c.device_rpid and ";
    String endClause = " order by a.user_rpid asc offset (?) rows fetch first (?) rows only";
    sql = sql.append("select distinct a.user_rpid, c.update_sequence  from rp_user_in_study a, rp_user_device b, rp_consent c where ");
    String dataSharScope =
        dbs.get().toSelect("select rp_data_sharing_scope from rp_researcher_data_access where rp_study_id = ? and"
            + " rp_sunet_id = ? ").argLong(studyId).argString(sunetId).queryStringOrNull();
    if (dataSharScope.equals("all_qualified_researchers")) {
      sql = sql.append(whereClause);
      sql = sql.append("c.data_sharing_scope = 'all_qualified_researchers' ");
      sql = sql.append(endClause);
      userIds =
          dbs.get().toSelect(sql)
              .argLong(studyId).argBoolean(true)
              .argInteger(offset).argInteger(fetchSize)
              .<ParticipantInfo>queryMany((r) -> {
                ParticipantInfo info = new ParticipantInfo();
                info.id = r.getLongOrNull();
                info.sequence = r.getLongOrNull();
                //info.name = r.getStringOrNull();
                return info;
              });
    } else if (dataSharScope.equals("sponsors_and_partners")) {
      sql = sql.append("(" + whereClause);
      sql = sql.append("c.data_sharing_scope = 'sponsors_and_partners' " + ")");
      sql = sql.append(" or (" + whereClause);
      sql = sql.append("c.data_sharing_scope = 'all_qualified_researchers'" + ")");
      sql = sql.append(endClause);
      userIds =
          dbs.get().toSelect(sql)
              .argLong(studyId).argBoolean(true).argLong(studyId).argBoolean(true)
              .argInteger(offset).argInteger(fetchSize)
              .<ParticipantInfo>queryMany((r) -> {
                ParticipantInfo info = new ParticipantInfo();
                info.id = r.getLongOrNull();
                info.sequence = r.getLongOrNull();
               // info.name = r.getStringOrNull();
                return info;
              });
    }
    return userIds;
  }

  public List<GenePoolParticipant> genePoolParticipants(Integer pg, Integer pageSize) {
    List<GenePoolParticipant> participants = new ArrayList<GenePoolParticipant>();
   Integer  fetchSize = pageSize + 1;
    Integer offset = ((pg - 1) * pageSize);
    Long genePoolStudyId = dbs.get().toSelect("select rp_study_id from rp_study where short_name=?")
        .argString("genepool")
        .queryLongOrNull();
    participants =
        dbs.get().toSelect("select a.name, a.date_of_birth, b.mrn, c.rp_user_id, d.email_address, b.order_status from rp_consent a, rp_genepool_consent b, rp_user_device c, rp_user_email d, rp_user_in_study e where a.device_rpid = b.device_rpid and c.device_rpid = b.device_rpid  and c.rp_user_id = d.rp_user_id and e.rp_user_id = d.rp_user_id and e.rp_study_id = ? and e.participation_status = ? order by a.agreed_time desc offset (?) rows fetch first (?) rows only").argLong(genePoolStudyId).argBoolean(true).argInteger(offset).argInteger(fetchSize)
            .<GenePoolParticipant>queryMany((r) -> {
              GenePoolParticipant participant = new GenePoolParticipant();
              participant.name = r.getStringOrNull();
              //SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
              LocalDateTime ldt = LocalDateTime.ofInstant(r.getDateOrNull().toInstant(), ZoneId.systemDefault());
              participant.birthDate = DateTimeFormatter.ISO_LOCAL_DATE.format(ldt);
              //participant.birthDate = formatter.format(r.getDateOrNull());
              participant.mrn = r.getStringOrNull();
              participant.userId = r.getLongOrNull();
              participant.email = r.getStringOrNull();
              participant.status = r.getStringOrNull();
              return participant;
            });
    return participants;

  }

  public Boolean verifyGenePoolAdmin(String sunetId) {
     Boolean admin = Boolean.FALSE;
     Long id = dbs.get().toSelect("select rp_study_id from rp_genepool_admin where rp_sunet_id = ? ").argString(sunetId).queryLongOrNull();
     if (id != null) {
        admin = Boolean.TRUE;
     }
     return admin;
  }

  public void updateGenePoolStatus(Long userId, String status) {
     dbs.get().toUpdate("update rp_genepool_consent set order_status = ? where device_rpid = (select device_rpid from rp_user_device where rp_user_id = ?)")
         .argString(status).argLong(userId).update(1);
  }

  public Long getApiTokenId(String sunetId) {

    Long id = dbs.get().toSelect("select rp_api_token_id from rp_api_token where rp_sunet_id = ?")
        .argString(sunetId).queryLongOrNull();

    return id;
  }

  public static class ApiToken {
    public Long apiTokenId;
    public String username;
    public Long studyId;
    public Long orgId;
    public String uncryptedToken;
    public String bcryptedToken;
    public Date validFrom;
    public Date validThru;
    public Long updateSequence;
    public Date updateTime;

  }

  public static class ShareInfo {
   public Long userId;
   public Boolean  shares;
  }

  public static class ParticipantInfo {
    public Long id;
    public Long sequence;
    //public String name;
  }

  public List<ApiToken> findApiTokensByUserAndStudy(String username, Long studyId) {
    return dbs.get()
        .toSelect("select rp_api_token_id, rp_sunet_id, rp_study_id, rp_org_id,uncrypted_token, bcrypted_token,"
        + " valid_from, valid_thru, update_sequence, update_time from rp_api_token"
        + " where rp_sunet_id=? and rp_study_id=?")
        .argString(username)
        .argLong(studyId)
        .queryMany(r -> {
          ApiToken token = new ApiToken();
          token.apiTokenId = r.getLongOrNull();
          token.username = r.getStringOrNull();
          token.studyId = r.getLongOrNull();
          token.orgId = r.getLongOrNull();
          token.uncryptedToken = r.getStringOrNull();
          token.bcryptedToken = r.getStringOrNull();
          token.validFrom = r.getDateOrNull();
          token.validThru = r.getDateOrNull();
          token.updateSequence = r.getLongOrNull();
          token.updateTime = r.getDateOrNull();
          return token;
        });

  }

  public ApiToken findApiTokenByToken(String tokenStr) {
    String uncryptedToken = tokenStr.substring(0, tokenStr.length() / 2);
    String secretToken = tokenStr.substring(tokenStr.length() / 2);

    return dbs.get()
        .toSelect("select rp_api_token_id, rp_sunet_id, rp_study_id, rp_org_id, uncrypted_token, bcrypted_token,"
        + " valid_from, valid_thru, update_sequence, update_time from rp_api_token"
        + " where uncrypted_token=? and valid_from <= :now and valid_thru > :now")
        .argString(uncryptedToken)
        .argDateNowPerDb("now")
        .queryOneOrNull(r -> {
          ApiToken token = new ApiToken();
          token.apiTokenId = r.getLongOrNull();
          token.username = r.getStringOrNull();
          token.studyId = r.getLongOrNull();
          token.orgId = r.getLongOrNull();
          token.uncryptedToken = r.getStringOrNull();
          token.bcryptedToken = r.getStringOrNull();
          token.validFrom = r.getDateOrNull();
          token.validThru = r.getDateOrNull();
          token.updateSequence = r.getLongOrNull();
          token.updateTime = r.getDateOrNull();

          if (OpenBSDBCrypt.checkPassword(token.bcryptedToken,secretToken.toCharArray())) {
            return token;
          }
          return null;
        });
  }

  /**
   * Create a token with which a user may access the researcher API for downloading data.
   * This is actually a refresh token that can be redeemed at the API end-point for a
   * real access token.
   *
   * @return the API token (refresh token)
   */
  public Token createOrReplaceApiToken(String username, Long studyId, int expireMinutes) {
    Database db = dbs.get();

    // Delete existing API tokens if there are any
    for (ApiToken apiToken : findApiTokensByUserAndStudy(username, studyId)) {
      deleteApiToken(apiToken);
    }

    // Generate a new token, half of which will be stored as a password hash (for verification)
    // and half of which will be stored in the clear (for lookup)
    String token = new SessionKeyGenerator(secureRandom).create(64);
    String uncryptedToken = token.substring(0, 32);
    byte[] salt = new byte[16];
    secureRandom.nextBytes(salt);
    String bcryptedToken = OpenBSDBCrypt.generate(token.substring(32).toCharArray(),salt,13);
    //Get the org_id for the user
    Sql sql = new Sql();
    sql.append("select rp_org_id from rp_researcher_data_access where rp_sunet_id = ? and rp_study_id = ?");
    Long orgId = db.toSelect(sql).argString(username).argLong(studyId).queryLongOrNull();

    sql = new Sql();
    sql.append(
        "insert into rp_api_token (rp_api_token_id, rp_sunet_id, rp_study_id,rp_org_id, uncrypted_token, bcrypted_token,"
            + " valid_from, valid_thru, update_sequence, update_time) values (:pk,?,?,?,?,:secret_bcrypt,?,(? + (interval '");
    sql.append(expireMinutes);
    sql.append("' minute)),0,?)");
    Long tokenId = db.toInsert(sql)
        .argPkSeq(":pk", "rp_pk_seq")
        .argString(username)
        .argLong(studyId)
        .argLong(orgId)
        .argString(uncryptedToken)
        .argString("secret_bcrypt",bcryptedToken)
        .argDateNowPerDb()
        .argDateNowPerDb()
        .argDateNowPerDb()
        .insertReturningPkSeq("rp_api_token_id");

    // Also insert in the history table
    sql = new Sql();
    sql.append(
        "insert into rp_api_token_history (rp_api_token_id, rp_sunet_id, rp_study_id, rp_org_id,uncrypted_token, "
            + "bcrypted_token, valid_from, valid_thru, update_sequence, update_time) values (?,?,?,?,?,:secret_bcrypt,?,(? + (interval '");
    sql.append(expireMinutes);
    sql.append("' minute)),0,?)");
    db.toInsert(sql)
        .argLong(tokenId)
        .argString(username)
        .argLong(studyId)
        .argLong(orgId)
        .argString(uncryptedToken)
        .argString("secret_bcrypt",bcryptedToken)
        .argDateNowPerDb()
        .argDateNowPerDb()
        .argDateNowPerDb()
        .insert(1);
    Date validDate = db.toSelect("select valid_thru from rp_api_token where rp_api_token_id = ?").argLong(tokenId).queryDateOrNull();
    Token result = new Token();
    result.token = token;
    result.validTo = validDate;
    return result;
  }

  public void deleteApiToken(ApiToken token) {
    Database db = dbs.get();
    // Insert the history row first, so it will fail (non-unique sample_id + update_sequence)
    // if someone else modified the row. This is an optimistic locking strategy.
    long newUpdateSequence = token.updateSequence + 1;
    Date newUpdateTime = db.nowPerApp();
    db.toInsert(
        "insert into rp_api_token_history (rp_api_token_id, rp_sunet_id, rp_study_id, rp_org_id, uncrypted_token,"
        + " bcrypted_token, valid_from, valid_thru, update_sequence, update_time, is_deleted)"
            + " values (?,?,?,?,?,:secret_bcrypt,?,?,?,?,'Y')")
        .argLong(token.apiTokenId)
        .argString(token.username)
        .argLong(token.studyId)
        .argLong(token.orgId)
        .argString(token.uncryptedToken)
        .argString("secret_bcrypt",token.bcryptedToken)
        .argDate(token.validFrom)
        .argDate(token.validThru)
        .argLong(newUpdateSequence)
        .argDate(newUpdateTime)
        .insert(1);

    db.toDelete("delete from rp_api_token where rp_api_token_id=?")
        .argLong(token.apiTokenId)
        .update(1);

    // Make sure the object in memory matches the database.
    token.updateSequence = newUpdateSequence;
    token.updateTime = newUpdateTime;
  }

  public void createAuth(Auth auth) {
    Long userId = findOrCreateUserIdByEmail(auth.email);

    dbs.get().toInsert("insert into rp_user_credential (rp_user_id, issuer, username_normalized,"
        + " username_display, password_type, password) values (?,?,?,?,?,?)")
        .argLong(userId)
        .argString("mypart")
        .argString(auth.usernameNormalized)
        .argString(auth.usernameDisplay)
        .argString("bcrypt")
        .argString(auth.password)
        .insert(1);

    auth.userId = userId;
  }

  public Auth authByEmail(String email) {
    return dbs.get().toSelect("select rp_user_id, username_normalized, username_display, password"
        + " from rp_user_credential where issuer='mypart' and"
        + " rp_user_id=(select rp_user_id from rp_user_email where email_address=?)")
        .argString(email).queryOneOrNull(r -> {
          Auth auth = new Auth();
          auth.email = email;
          auth.userId = r.getLongOrNull();
          auth.usernameNormalized = r.getStringOrEmpty();
          auth.usernameDisplay = r.getStringOrEmpty();
          auth.displayName = auth.usernameDisplay; // TODO not right
          auth.password = r.getStringOrEmpty();
          return auth;
        });
  }

  public Auth authByUserId(Long userId) {
    return dbs.get().toSelect("select username_normalized, username_display, password"
        + " from rp_user_credential where rp_user_id=?")
        .argLong(userId).queryOneOrNull(r -> {
          Auth auth = new Auth();
          auth.email = null; // TODO
          auth.userId = userId;
          auth.usernameNormalized = r.getStringOrEmpty();
          auth.usernameDisplay = r.getStringOrEmpty();
          auth.displayName = auth.usernameDisplay; // TODO not right
          auth.password = r.getStringOrEmpty();
          return auth;
        });
  }

  public Code createAuthCode(String clientId, String scope, Auth authToCheck) {
    Date now = dbs.get().nowPerApp();
    Code code = new Code();
    code.code = new SessionKeyGenerator(secureRandom).create(16);
    code.expires = now.toInstant().plus(1, ChronoUnit.MINUTES);
    code.clientId = clientId;
    code.scope = scope;
    code.auth = authToCheck;

    dbs.get().toInsert("insert into rp_temporary_auth_code (code, create_time, expire_time, client_id, scope,"
        + " rp_user_id) values (?,?,?,?,?,?)")
        .argString(code.code)
        .argDate(now)
        .argDate(Date.from(code.expires))
        .argString(clientId)
        .argString(scope)
        .argLong(authToCheck.userId).insert(1);

    return code;
  }

  public Code tempAuthCodeByCode(String code) {
    return dbs.get().toSelect("select expire_time, client_id, scope, rp_user_id"
        + " from rp_temporary_auth_code where code=?")
        .argString(code).queryOneOrNull(r -> {
          Code result = new Code();
          result.code = code;
          Date expires = r.getDateOrNull();
          result.expires = expires == null ? null : expires.toInstant();
          result.clientId = r.getStringOrNull();
          result.scope = r.getStringOrNull();
          result.auth = authByUserId(r.getLongOrNull());
          return result;
        });
  }

  public Study studyByShortName(String shortName) {
    return dbs.get().toSelect("select rp_study_id, short_name, display_name from rp_study where short_name=?")
        .argString(shortName).queryOneOrNull(r -> {
          Study study = new Study();
          study.studyId = r.getLongOrNull();
          study.shortName = r.getStringOrNull();
          study.displayName = r.getStringOrNull();
          return study;
        });
  }

  public Study createStudy(String shortName, String displayName) {
    Study study = new Study();
    study.studyId = dbs.get().toInsert("insert into rp_study (rp_study_id,short_name,display_name) values (?,?,?)")
        .argPkSeq("rp_pk_seq")
        .argString(shortName)
        .argString(displayName)
        .insertReturningPkSeq("rp_study_id");
    study.shortName = shortName;
    study.displayName = displayName;

    return study;
  }

  public StudyApp studyAppByClientId(String clientId) {
    return dbs.get().toSelect("select rp_study_app_id, rp_study_id, client_id, client_secret, redirect_uri"
        + " from rp_study_app where client_id=?")
        .argString(clientId).queryOneOrNull(r -> {
          StudyApp studyApp = new StudyApp();
          studyApp.studyAppId = r.getLongOrNull();
          studyApp.studyId = r.getLongOrNull();
          studyApp.clientId = r.getStringOrNull();
          studyApp.clientSecret = r.getStringOrNull();
          studyApp.redirectUri = r.getStringOrNull();
          return studyApp;
        });
  }

  /**
   * @return the client secret, unencrypted (the value stored in the database is encrypted)
   */
  public String createStudyApp(Study study, String clientId, String redirectUri) {
    String clientSecret = new SessionKeyGenerator(secureRandom).create(64);
    byte[] salt = new byte[16];
    secureRandom.nextBytes(salt);
    dbs.get().toInsert("insert into rp_study_app (rp_study_app_id, rp_study_id, client_id,"
        + " client_secret, redirect_uri) values (?,?,?,:secret,?)")
        .argPkSeq("rp_pk_seq")
        .argLong(study.studyId)
        .argString(clientId)
        .argString("secret", OpenBSDBCrypt.generate(clientSecret.toCharArray(),salt,13))
        .argString(redirectUri)
        .insert(1);

    return clientSecret;
  }

  /**
   * @return the email token for inclusion in the email link
   */
  public String createSignup(String email) {
    String emailToken = new SessionKeyGenerator(secureRandom).create(64);

    dbs.get().toInsert("insert into rp_signup_request (email_token, email_recipient, "
        + " email_create_time) values (?,?,?)")
        .argString(emailToken)
        .argString(email)
        .argDateNowPerDb()
        .insert(1);

    return emailToken;
  }

  public void signupSent(String emailToken, boolean sent) {
    dbs.get().toUpdate("update rp_signup_request set email_send_time=?, email_successful=?"
        + " where email_token=?")
        .argDateNowPerDb()
        .argBoolean(sent)
        .argString(emailToken)
        .update(1);
  }

  public Signup signupBySignupToken(String token) {
    return dbs.get().toSelect("select email_recipient, email_token, email_create_time,"
        + " email_send_time, email_successful, verify_time from rp_signup_request"
        + " where email_token=? and email_send_time + interval '24' hour > ?")
        .argString(token)
        .argDateNowPerDb()
        .queryOneOrNull(r -> {
          Signup signup = new Signup();
          signup.email = r.getStringOrNull();
          signup.emailToken = r.getStringOrNull();
          signup.createTime = r.getDateOrNull();
          signup.sendTime = r.getDateOrNull();
          signup.emailSuccessful = r.getBooleanOrNull();
          signup.verifyTime = r.getDateOrNull();
          return signup;
        });
  }

  public Signup signupByPasswordResetToken(String token) {
    return dbs.get().toSelect("select email_recipient, email_token, email_create_time,"
        + " email_send_time, email_successful, verify_time from rp_signup_request"
        + " where password_reset_token=? and verify_time + interval '5' minute > ?")
        .argString(token)
        .argDateNowPerDb()
        .queryOneOrNull(r -> {
          Signup signup = new Signup();
          signup.email = r.getStringOrNull();
          signup.emailToken = r.getStringOrNull();
          signup.createTime = r.getDateOrNull();
          signup.sendTime = r.getDateOrNull();
          signup.emailSuccessful = r.getBooleanOrNull();
          signup.verifyTime = r.getDateOrNull();
          return signup;
        });
  }

  /**
   * Make sure the provided token is valid per any business rules that apply,
   * and update the verify_time if verified.
   *
   * @param token the unique signup token to check
   * @return a token to reset the password if verified; null if not verified
   */
  public String verifySignupToken(String token) {
    Signup signup = signupBySignupToken(token);
    String passwordResetToken = null;

    if (signup != null && signup.emailSuccessful && signup.verifyTime == null) {
      passwordResetToken = new SessionKeyGenerator(secureRandom).create(32);
      dbs.get().toUpdate("update rp_signup_request set verify_time=?, password_reset_token=?"
          + " where email_token=?")
          .argDateNowPerDb()
          .argString(passwordResetToken)
          .argString(token).update(1);
    }
    return passwordResetToken;
  }

  public boolean resetPassword(String passwordResetToken, String password) {
    Signup signup = signupByPasswordResetToken(passwordResetToken);

    if (signup != null && signup.emailSuccessful && signup.verifyTime != null && signup.passwordResetTime == null
        && signup.verifyTime.toInstant().isAfter(Instant.now().minus(5, ChronoUnit.MINUTES))) {
      Long userId = findOrCreateUserIdByEmail(signup.email);
      Auth auth = authByUserId(userId);
      byte[] salt = new byte[16];
      secureRandom.nextBytes(salt);
      if (auth == null) {
        auth = new Auth();
        auth.email = signup.email;
        auth.password = OpenBSDBCrypt.generate(password.toCharArray(), salt,13);
        // TODO figure out what to do about usernames (may not want to automatically disclose emails)
        auth.usernameNormalized = "<hidden>";
        auth.usernameDisplay = "<hidden>";
        auth.displayName = "<hidden>";
        createAuth(auth);
      } else {
        auth.password = OpenBSDBCrypt.generate(password.toCharArray(), salt,13);
        dbs.get().toUpdate("update rp_user_credential set password_type=?, password=? where rp_user_id=?")
            .argString("bcrypt")
            .argString(auth.password)
            .argLong(auth.userId)
            .update(1);
      }
      dbs.get().toUpdate("update rp_signup_request set password_reset_time=? where password_reset_token=?")
          .argDateNowPerDb().argString(passwordResetToken).update(1);
      return true;
    } else {
      return false;
    }
  }

  public List<Signup> recentSignupsByEmail(String email) {
    return dbs.get().toSelect("select email_recipient, email_token, email_create_time,"
        + " email_send_time, email_successful, verify_time from rp_signup_request"
        + " where email_recipient=? and email_send_time + interval '24' hour > ? order by email_send_time desc")
        .argString(email)
        .argDateNowPerDb()
        .queryMany(r -> {
          Signup signup = new Signup();
          signup.email = r.getStringOrNull();
          signup.emailToken = r.getStringOrNull();
          signup.createTime = r.getDateOrNull();
          signup.sendTime = r.getDateOrNull();
          signup.emailSuccessful = r.getBooleanOrNull();
          signup.verifyTime = r.getDateOrNull();
          return signup;
        });
  }

  public static class DeviceEmail {
    public String deviceRpid;
    public String deciveDescription;
    public String emailRecipient;
  }

  public static class Code {
    public String code;
    public Instant expires;
    public String clientId;
    public String scope;
    public Auth auth;

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      Code code1 = (Code) o;
      return Objects.equals(code, code1.code)
          && Objects.equals(expires, code1.expires)
          && Objects.equals(clientId, code1.clientId)
          && Objects.equals(scope, code1.scope);
    }

    @Override
    public int hashCode() {
      return Objects.hash(code, expires, clientId, scope);
    }
  }

  public static class Auth {
    public Long userId;
    public String usernameNormalized;
    public String usernameDisplay;
    public String email;
    public String password;
    public String displayName;
  }

  public static class UserInfo {
    public Long userRpid;
    public Long rpUserid;
    public String deviceRpid;
  }

  public static class Signup {
    public String emailToken;
    public String email;
    public Date createTime;
    public Date sendTime;
    public Boolean emailSuccessful;
    public Date verifyTime;
    public Date passwordResetTime;
  }

  public static class Client {
    public String clientId;
    public String clientSecret;
    public String redirectUri;
  }

  public static class Study {
    public Long studyId;
    public String shortName;
    public String displayName;
  }

  public static class StudyApp {
    public Long studyAppId;
    public Long studyId;
    public String clientId;
    public String clientSecret;
    public String redirectUri;
  }

  public static class GenePoolParticipant {
    public String name;
    public String  birthDate;
    public String mrn;
    public Long userId;
    public String status;
    public String email;
  }

  public static class User {
    public Long updateSeq;
    public Long userRpid;
  }

  public static class Token {
    public String token;
    public Date  validTo;
  }
}
