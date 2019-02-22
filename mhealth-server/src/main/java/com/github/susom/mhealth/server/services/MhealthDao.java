package com.github.susom.mhealth.server.services;

import com.github.susom.database.Database;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

public class MhealthDao {
  private Supplier<Database> dbp;
  private final long scoperId;

  public MhealthDao(Supplier<Database> dp, long scoperId) {
    dbp = dp;
    this.scoperId = scoperId;
  }

  public Long createDeviceApp(DeviceApp deviceApp) {
    return dbp.get().toInsert("insert into mh_device_app (mh_device_app_id, mh_scoper_id, app_key, app_key_type,"
        + " device_rpid) values (:pk,?,:secret_appKey,?,?)")
        .argPkSeq(":pk", "mh_pk_seq")
        .argLong(scoperId)
        .argString("secret_appKey", deviceApp.getAppKey())
        .argString(deviceApp.getAppKeyType())
        .argString(deviceApp.getDeviceRpid()).insertReturningPkSeq("mh_device_app_id");
  }

  public Long createDeviceApp(Long scoperId, String appKey, String appType, String deviceRpid) {
    return dbp.get().toInsert("insert into mh_device_app (mh_device_app_id, mh_scoper_id, app_key, app_key_type,"
        + " device_rpid) values (:pk,?,:secret_appKey,?,?)")
        .argPkSeq(":pk", "mh_pk_seq")
        .argLong(scoperId)
        .argString("secret_appKey", appKey)
        .argString(appType)
        .argString(deviceRpid).insertReturningPkSeq("mh_device_app_id");
  }

  public void createFileUpload(SecureRandom secureRandom, Long studyId, String deviceRpid,  byte[] content) {
    String id = new SessionKeyGenerator(secureRandom).create();

    Long fileUploadId = dbp.get().toInsert("insert into mh_file_upload (mh_file_upload_id, mh_scoper_id, mh_device_app_id,"
        + "upload_token, requested_time,completed_time) values (?,?,(select mh_device_app_id from mh_device_app where device_rpid=?),?,?,?)")
        .argPkSeq("mh_pk_seq").argLong(studyId).argString(deviceRpid).argString(id).argDateNowPerDb().argDateNowPerDb()
        .insertReturningPkSeq("mh_file_upload_id");

    dbp.get().toInsert("insert into mh_file_upload_content (mh_file_upload_id, content) values (?,?)")
        .argLong(fileUploadId).argBlobBytes(content).insert(1);


  }

  public static class Identity {
    public String username;
    public Long studyId;
    public Long orgId;
  }

  /**
   * Determine the user identity from an access (session) token. The token should
   * already be validated for legal characters and length. It will be split in half,
   * and the first half will be used as the lookup key, the second half will be used
   * to check the bcrypted portion.
   *
   * @return the identity, or null if token could not be found, is expired, the bcrypt did not match, etc.
   */
  public Identity identityByToken(String sessionToken) {
    String lookupToken = sessionToken.substring(0, sessionToken.length() / 2);
    String verifyToken = sessionToken.substring(sessionToken.length() / 2);

    return dbp.get().toSelect("select bcrypted_token,sunet_id,study_id,org_id from mh_access_token"
        + " where uncrypted_token=? and ? <= valid_thru")
        .argString(lookupToken)
        .argDateNowPerDb()
        .queryOneOrNull(r -> {
          if (OpenBSDBCrypt.checkPassword(r.getStringOrEmpty(),verifyToken.toCharArray())) {
            Identity identity = new Identity();
            identity.username = r.getStringOrNull();
            identity.studyId = r.getLongOrNull();
            identity.orgId = r.getLongOrNull();
            return identity;
          }
          return null;
        });
  }

  public Long createMhUserProfile(Long userRpid) {

    return dbp.get().toInsert("insert into mh_user_profile (mh_user_profile_id,mh_scoper_id,user_rpid) values(?,?,?)")
        .argPkSeq("mh_pk_seq").argLong(this.scoperId).argLong(userRpid).insertReturningPkSeq("mh_user_profile_id");

  }

  public List<Long> getMhDeviceAppIdForUserId(List<Long> userRpids) {
    ArrayList<Long> mhDeviceAppIds = new ArrayList<Long>();
    for (Long userRpid : userRpids) {
      Long mhUserProfileId =
          dbp.get().toSelect("select mh_user_profile_id from mh_user_profile where user_rpid = ?")
              .argLong(userRpid).queryLongOrNull();
      Long mhDeviceAppId = dbp.get()
          .toSelect("select mh_device_app_id from mh_device_app where mh_user_profile_id = ?")
          .argLong(mhUserProfileId).queryLongOrNull();
      mhDeviceAppIds.add(mhDeviceAppId);
    }
    return mhDeviceAppIds;
  }

  public void updateMhDeviceApp(String deviceRpid, Long mhUserProfileId) {
    dbp.get().toUpdate("update mh_device_app set mh_user_profile_id = ? where device_rpid = ?").argLong(mhUserProfileId)
        .argString(deviceRpid).update(1);
  }

  public Long getMhUserProfileId(Long userRpid) {
    return dbp.get().toSelect("select mh_user_profile_id from mh_user_profile where user_rpid = ?").argLong(userRpid)
        .queryLongOrNull();
  }

//  public void sendVerificationEmail(Properties appProperties, String email, long verificationToken, Mailer mailer)
//
//  {
//
//    InputStream inS = Thread.currentThread().getContextClassLoader().getResourceAsStream("email-verification.txt");
//    Scanner scn = new Scanner(inS);
//    String verifyEmail = scn.useDelimiter("\\Z").next();
//    scn.close();
//
//    String url = appProperties.get("host") + "mhc/api/v3/auth/verifyEmail/" + verificationToken;
//
//    HashMap<String, String> map = new HashMap<>();
//    map.put("studyName", (String) appProperties.get("study.name"));
//    map.put("url", url);
//    map.put("sponsorName", (String) appProperties.get("study.sponsor.name"));
//    map.put("supportEmail", (String) appProperties.get("study.support.email"));
//    String verifiedMail = Util.resolveHtmlTemplate(verifyEmail, map);
//    mailer.sendHtml((String) appProperties.get("study.support.email"), null, email, null, null, "Verify your Account",
//        verifiedMail);
//
//  }

//  public String getEmail(String userName) {
//    return dbp.get().toSelect("select email from users where username = ?").argString(userName)
//        .queryStringOrNull();
//
//  }

//  public boolean samePassword(String userName, String passwd) {
//    return dbp.get().toSelect("select password from users where username = ?").argString(userName).query(rs -> {
//      if (rs.next()) {
//        String password = rs.getStringOrNull();
//        if (password.equals(passwd))
//          return true;
//        else
//          return false;
//      }
//      return false;
//    });
//
//  }

//  public Integer getUserIdFromName(String userName) {
//    return dbp.get().toSelect("select user_id from users where username = ?").argString(userName)
//        .queryIntegerOrNull();
//  }

//  public Integer getUserIdFromSession(String sessionToken) {
//    return dbp.get().toSelect("select user_id from users where sessionToken = ?").argString(sessionToken)
//        .queryIntegerOrNull();
//  }

//  public String getUserNameFromSession(String sessionToken) {
//    return dbp.get().toSelect("select username from users where sessionToken = ?").argString(sessionToken)
//        .queryStringOrNull();
//  }

//  public String getFullName(String userName) {
//    Integer user_id = getUserIdFromName(userName);
//    return dbp.get().toSelect("select name from consents where user_id = ?").argInteger(user_id).queryStringOrNull();
//  }

//  public Long getVerificationToken(String email) {
//    return dbp.get().toSelect("select verificationToken from users where email = ?").argString(email).queryLongOrNull();
//  }

//  public void saveConsent(Consent cons) {
//
//    /*
//     * dbp.get() .toInsert(
//     * "insert into consents (user_id, name, signingDate,birthDate,scope,htmlconsent,pdfconsent) " +
//     * "values (?,?,?,?,?,?,?)")
//     * .argInteger(cons.getUserId()).argString(cons.getName()).argString(cons.getSigningDate())
//     * .argString(cons.getBirthDate()).argString(cons.getScope()).argClobString(cons.getHtmlConsent(
//     * )) .argBlobBytes(cons.getPdfConsent()).insert(1);
//     */
//
//  }

//  public void requestPasswordReset(String email) {}

//  public Boolean isVerified(String userName) {
//
//    return dbp.get().toSelect("select verified from users where username = ?").argString(userName)
//        .queryBooleanOrFalse();
//
//  }

//  public Boolean isVerified(Long verificationToken) {
//    return dbp.get().toSelect("select verified from users where verificationtoken = ?").argLong(verificationToken)
//        .queryBooleanOrFalse();
//  }

//  public void updateScope(Integer userId, String scope) {
//    dbp.get().toUpdate("Update consents set scope = ? where user_id = ? ")
//        .argString(scope).argInteger(userId)
//        .update(1);
//  }

//  public String getScope(Integer userId) {
//
//    return dbp.get().toSelect("select scope from consents where user_id = ?").argInteger(userId).queryStringOrNull();
//  }

//  public Integer consented(Integer userID) {
//
//    return dbp.get().toSelect("select user_id from consents where user_id = ?").argInteger(userID).queryIntegerOrNull();
//
//  }

//  public Integer consented(String sessionToken) {
//    Integer userId = getUserIdFromSession(sessionToken);
//    return consented(userId);
//
//  }

//  public void verify(long token) {
//    dbp.get().toUpdate("Update users set verified = 'Y' where verificationToken = ? ")
//        .argLong(token).update(1);
//  }

//  public void insertSessionToken(Integer id, String token) {
//    dbp.get().toUpdate("Update users set sessiontoken = ? where user_id = ? ").argString(token).argInteger(id)
//        .update(1);
//  }

//  public String validSessionToken(String token) {
//
//    return dbp.get().toSelect("select sessionToken from users where sessionToken = ?").argString(token)
//        .queryStringOrNull();
//
//  }

}
