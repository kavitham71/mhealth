package com.github.susom.mhealth.server.tools;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProvider;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility to create a database schema for this application.
 */
public class CreateScalabilityDatabase {
  @SuppressWarnings("tainting") // anything we can do, whoever gave us the database credentials can do
  public static void main(String[] args) {
    try {
      Set<String> argSet = new HashSet<>(Arrays.asList(args));
      String propertiesFile = System.getProperty("local.properties", "local.properties");
      Config config = Config.from().systemProperties().propertyFile(propertiesFile).get();
      String databaseUrl = config.getString("database.url");
      if (databaseUrl != null) {
        String databaseUser = config.getString("database.user");
        String databasePassword = config.getString("database.password");
        String[][] userData = new String[][] {
            { "111", "MyHeart Counts iOS App", "me1@gmail.com", "1111", "111111", "111", "111", "11111", "111", "111",
                "me1@gmail.com" },
            { "222", "MyHeart Counts iOS App", "me2@gmail.com", "2222", "222222", "222", "222", "22222", "222", "222",
                "me2@gmail.com" },
            { "333", "MyHeart Counts iOS App", "me3@gmail.com", "3333", "333333", "333", "333", "33333", "333", "333",
                "me3@gmail.com" },
            { "444", "MyHeart Counts iOS App", "me4@gmail.com", "4444", "444444", "444", "444", "44444", "444", "444",
                "me4@gmail.com" },
            { "555", "MyHeart Counts iOS App", "me5@gmail.com", "5555", "555555", "555", "555", "55555", "555", "555",
                "me5@gmail.com" },
            { "666", "MyHeart Counts iOS App", "me6@gmail.com", "6666", "666666", "666", "666", "66666", "666", "666",
                "me46gmail.com" },
            { "777", "MyHeart Counts iOS App", "me7@gmail.com", "7777", "777777", "777", "777", "77777", "777", "777",
                "me7@gmail.com" },
            { "888", "MyHeart Counts iOS App", "me8@gmail.com", "8888", "888888", "888", "888", "88888", "888", "888",
                "me48gmail.com" },
            { "999", "MyHeart Counts iOS App", "me9@gmail.com", "9999", "999999", "999", "999", "99999", "999", "999",
                "me9@gmail.com" },
            { "101", "MyHeart Counts iOS App", "me10@gmail.com", "1010", "101010", "101", "101", "10101", "101", "101",
                "me10@gmail.com" },
            { "102", "MyHeart Counts iOS App", "me11@gmail.com", "1021", "102102", "102", "102", "10210", "102", "102",
                "me11@gmail.com" },
            { "103", "MyHeart Counts iOS App", "me12@gmail.com", "1031", "103103", "103", "103", "10310", "103", "103",
                "me12@gmail.com" },
            { "104", "MyHeart Counts iOS App", "me13@gmail.com", "1041", "104104", "104", "104", "10410", "104", "104",
                "me13@gmail.com" },
            { "105", "MyHeart Counts iOS App", "me14@gmail.com", "1051", "105105", "105", "105", "10510", "105", "105",
                "me14@gmail.com" },
            { "106", "MyHeart Counts iOS App", "me15@gmail.com", "1061", "106106", "106", "106", "10610", "106", "106",
                "me15@gmail.com" },
            { "107", "MyHeart Counts iOS App", "me16@gmail.com", "1071", "107107", "107", "107", "10710", "107", "107",
                "me16@gmail.com" },
            { "108", "MyHeart Counts iOS App", "me17@gmail.com", "1081", "108108", "108", "108", "10810", "108", "108",
                "me17@gmail.com" },
            { "109", "MyHeart Counts iOS App", "me18@gmail.com", "1091", "109109", "109", "109", "10910", "109", "109",
                "me18@gmail.com" },
            { "200", "MyHeart Counts iOS App", "me19@gmail.com", "2002", "200200", "200", "200", "20020", "200", "200",
                "me19@gmail.com" },
            { "201", "MyHeart Counts iOS App", "me20@gmail.com", "2012", "201201", "201", "201", "20120", "201", "201",
                "me20@gmail.com" },
            { "202", "MyHeart Counts iOS App", "me21@gmail.com", "2022", "202202", "202", "202", "20220", "202", "202",
                "me21@gmail.com" },
            { "203", "MyHeart Counts iOS App", "me22@gmail.com", "2032", "203203", "203", "203", "20320", "203", "203",
                "me22@gmail.com" },
            { "204", "MyHeart Counts iOS App", "me23@gmail.com", "2042", "204204", "204", "204", "20420", "204", "204",
                "me24@gmail.com" },
            { "205", "MyHeart Counts iOS App", "me24@gmail.com", "2052", "205205", "205", "205", "20520", "205", "205",
                "me24@gmail.com" },
            { "206", "MyHeart Counts iOS App", "me25@gmail.com", "2062", "206206", "206", "206", "20620", "206", "206",
                "me25@gmail.com" },
            { "207", "MyHeart Counts iOS App", "me26@gmail.com", "2072", "207207", "207", "207", "20720", "207", "207",
                "me26@gmail.com" },
            { "208", "MyHeart Counts iOS App", "me27@gmail.com", "2082", "208208", "208", "208", "20820", "208", "208",
                "me27@gmail.com" },
            { "209", "MyHeart Counts iOS App", "me28@gmail.com", "2092", "209209", "209", "209", "20920", "209", "209",
                "me28@gmail.com" },
            { "300", "MyHeart Counts iOS App", "me29@gmail.com", "3003", "300300", "300", "300", "30030", "300", "300",
                "me29@gmail.com" },
            { "301", "MyHeart Counts iOS App", "me30@gmail.com", "3013", "301301", "301", "301", "30130", "301", "301",
                "me30@gmail.com" },
            { "302", "MyHeart Counts iOS App", "me31@gmail.com", "3023", "302302", "302", "302", "30230", "302", "302",
                "me31@gmail.com" },
            { "303", "MyHeart Counts iOS App", "me32@gmail.com", "3033", "303303", "303", "303", "30330", "303", "303",
                "me32@gmail.com" },
            { "304", "MyHeart Counts iOS App", "me33@gmail.com", "3043", "304304", "304", "304", "30430", "304", "304",
                "me33@gmail.com" },
            { "305", "MyHeart Counts iOS App", "me34@gmail.com", "3053", "305305", "305", "305", "30530", "305", "305",
                "me34@gmail.com" },
            { "306", "MyHeart Counts iOS App", "me35@gmail.com", "3063", "306306", "306", "306", "30630", "306", "306",
                "me35@gmail.com" },
            { "307", "MyHeart Counts iOS App", "me36@gmail.com", "3073", "307307", "307", "307", "30730", "307", "307",
                "me36@gmail.com" },
            { "308", "MyHeart Counts iOS App", "me37@gmail.com", "3083", "308308", "308", "308", "30830", "308", "308",
                "me37@gmail.com" },
            { "309", "MyHeart Counts iOS App", "me38@gmail.com", "3093", "309309", "309", "309", "30930", "309", "309",
                "me38@gmail.com" },
            { "400", "MyHeart Counts iOS App", "me39@gmail.com", "4004", "400400", "400", "400", "40040", "400", "400",
                "me39@gmail.com" },
            { "401", "MyHeart Counts iOS App", "me40@gmail.com", "4014", "401401", "401", "401", "40140", "401", "401",
                "me40@gmail.com" },
            { "402", "MyHeart Counts iOS App", "me41@gmail.com", "4024", "402402", "402", "402", "40240", "402", "402",
                "me41@gmail.com" },
            { "403", "MyHeart Counts iOS App", "me42@gmail.com", "4034", "403403", "403", "403", "40340", "403", "403",
                "me42@gmail.com" },
            { "404", "MyHeart Counts iOS App", "me43@gmail.com", "4044", "404404", "404", "404", "40440", "404", "404",
                "me43@gmail.com" },
            { "405", "MyHeart Counts iOS App", "me44@gmail.com", "4054", "405405", "405", "405", "40540", "405", "405",
                "me44@gmail.com" },
            { "406", "MyHeart Counts iOS App", "me45@gmail.com", "4064", "406406", "406", "406", "40640", "406", "406",
                "me45@gmail.com" },
            { "407", "MyHeart Counts iOS App", "me46@gmail.com", "4074", "407407", "407", "407", "40740", "407", "407",
                "me46@gmail.com" },
            { "408", "MyHeart Counts iOS App", "me47@gmail.com", "4084", "408408", "408", "408", "40840", "408", "408",
                "me47@gmail.com" },
            { "409", "MyHeart Counts iOS App", "me48@gmail.com", "4094", "409409", "409", "409", "40940", "409", "409",
                "me48@gmail.com" },
            { "500", "MyHeart Counts iOS App", "me49@gmail.com", "5005", "500500", "500", "500", "50050", "500", "500",
                "me49@gmail.com" },
            { "501", "MyHeart Counts iOS App", "me50@gmail.com", "5015", "501501", "501", "501", "50150", "501", "501",
                "me50@gmail.com" },

        };
        if (argSet.contains("-create")) {
          DatabaseProvider.fromDriverManager(databaseUrl, databaseUser, databasePassword).transact(dbp -> {
            for (String[] object : userData) {
              dbp.get().toInsert(
                  "insert into rp_device_register_request (device_rpid, device_description, email_recipient, email_token, email_create_time) values (?,?,?,?,?)")
                  .argString(object[0]).argString(object[1]).argString(object[2]).argString(object[3])
                  .argDateNowPerDb().insert(1);

              Long userId = dbp.get().toInsert("insert into rp_user (rp_user_id) values (?)").argPkSeq("rp_pk_seq")
                  .insertReturningPkSeq("rp_user_id");

              dbp.get()
                  .toInsert(
                      "insert into rp_user_in_study(rp_user_id,rp_study_id,user_rpid,participation_status) values(?,?,?,?)")
                  .argLong(userId).argLong(1L).argLong(Long.parseLong(object[4])).argBoolean(true).insert(1);

              dbp.get().toInsert("insert into rp_user_device (device_rpid, rp_user_id, enabled) values (?,?,?)")
                  .argString(object[5]).argLong(userId).argBoolean(true).insert(1);

              dbp.get()
                  .toUpdate(
                      "update rp_device_register_request set email_send_time= ?, email_successful= ?  where device_rpid=?")
                  .argDateNowPerDb().argBoolean(true).argString(object[6]).update(1);

              dbp.get()
                  .toInsert(
                      "insert into mh_device_app (mh_device_app_id, mh_scoper_id, app_key, app_key_type, device_rpid) values (?,?,?,?,?)")
                  .argLong(Long.parseLong(object[7])).argLong((long) 1).argString(
                  "$2a$10$zgA5BRgA4m5SOAOfEatYkuq6NQ53ohfY1/YIkiaa85fI4BNvtisNm").argString("password_bcrypted")
                  .argString(
                      object[8])
                  .insert(1);

              dbp.get()
                  .toInsert(
                      "insert into rp_consent (rp_study_id,device_rpid,name,agreed_time,date_of_birth,data_sharing_scope,html_consent,pdf_consent)"
                          + " values(?,?,?,?,?,?,?,?)")
                  .argLong(1L).argString(object[9]).argString(object[10]).argDateNowPerDb().argDateNowPerDb()
                  .argString("ALL_QUALIFIED_RESEARCHERS").argClobString(null).argBlobBytes(null).insert(1);

            }
          });
        } else if (argSet.contains("-delete")) {
          DatabaseProvider.fromDriverManager(databaseUrl, databaseUser, databasePassword).transact(dbp -> {
            dbp.get().toDelete("delete from rp_device_register_request").update(50);
            dbp.get().toDelete("delete from rp_user_device").update(50);
            dbp.get().toDelete("delete from rp_user_in_study").update(50);
            dbp.get().toDelete("delete from rp_user").update(50);
            dbp.get().toDelete("delete from mh_device_app").update(50);
            dbp.get().toDelete("delete from rp_consent").update(50);
          });
        }

      }
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
