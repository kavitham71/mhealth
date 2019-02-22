package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProvider;
import com.github.susom.database.DatabaseProvider.Builder;
import com.github.susom.database.OptionsOverride;
import com.github.susom.database.Sql;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.ApiToken;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.TimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * Unit test to check created token with BouncyCastle old version(v1.55)
 */
public class BouncyDbTest {

  private Builder dbb;
  private SecureRandom secureRandom;
  private Config config;

  /* Generated using bouncy castle version 1.55 */
  private final String token = "1gumj4j0d472zi19fgq3cqbglp7wkkcf8damb12x59kh761a1t124eh15cd1tprr";
  private static Long tokenId;

  @Before
  public void setUp() throws Exception {
    String propertiesFile = System.getProperty("local.properties", "../local.properties");
    config = Config.from().systemProperties().propertyFile(propertiesFile.split(":")).get();
    dbb = DatabaseProvider.pooledBuilder(config).withOptions(new OptionsOverride() {
      @Override
      public Calendar calendarForTimestamps() {
        return Calendar.getInstance(TimeZone.getTimeZone("America/Los_Angeles"));
      }
    }).withSqlParameterLogging();
    secureRandom = new SecureRandom();

    /* Token Insertion generated using bouncyCastle v1.55*/
    dbb.transact(dbp -> {
      Sql sql = new Sql();

      sql = new Sql();
      sql.append(
          "insert into rp_api_token (rp_api_token_id, rp_sunet_id, rp_study_id,rp_org_id, uncrypted_token, bcrypted_token,"
              + " valid_from, valid_thru, update_sequence, update_time) values (:pk,?,?,?,?,:secret_bcrypt,?,(? + (interval '");
      sql.append(120);
      sql.append("' minute)),0,?)");
      Long tokenId = dbp.get().toInsert(sql)
          .argPkSeq(":pk", "rp_pk_seq")
          .argString("testing1")
          .argLong(300L)
          .argLong(1L)
          .argString("1gumj4j0d472zi19fgq3cqbglp7wkkcf")
          .argString("secret_bcrypt",
              "$2a$13$A1MpLqux5T5vy4A6lQDDJeq2TQclDu/EJScn29ykfnTPDcp.3/yyW")
          .argDateNowPerDb()
          .argDateNowPerDb()
          .argDateNowPerDb()
          .insertReturningPkSeq("rp_api_token_id");
    });
  }

  @After
  public void tearDown() {
    dbb.transact(dbp -> {
      dbp.get().toDelete("delete from rp_api_token where rp_api_token_id=?")
          .argLong(tokenId)
          .update(1);
    });

    dbb.close();
  }

  /*Testing inserted token in database after BouncyCastle version upgrade */
  @Test
  public void testToken() {
    dbb.transact(dbp -> {
      MyPartDao dao = new MyPartDao(dbp, secureRandom);
      ApiToken apiTokenResponse = dao.findApiTokenByToken(token);
      tokenId = apiTokenResponse.apiTokenId;
      assertNotNull(apiTokenResponse);
    });
  }

}
