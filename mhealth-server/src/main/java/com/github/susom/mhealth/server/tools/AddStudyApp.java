package com.github.susom.mhealth.server.tools;

import com.github.susom.database.DatabaseProvider;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.Study;
import com.github.susom.mhealth.server.services.MyPartDao.StudyApp;
import java.security.SecureRandom;

/**
 * Utility for adding studies to the database for testing purposes.
 */
public class AddStudyApp {
  public static void main(String[] args) {
    try {
      DatabaseProvider.fromPropertyFileOrSystemProperties("local.properties")
          .withSqlParameterLogging()
          .transact(db -> {
            MyPartDao dao = new MyPartDao(db, new SecureRandom());

            Study study = dao.studyByShortName("mystudy");
            if (study == null) {
              study = dao.createStudy("mystudy", "Sample Study");
            }

            String clientId = "abc1234";
            String redirectUri = "http://localhost:8004/mystudy/callback";
            StudyApp studyApp = dao.studyAppByClientId(clientId);
            if (studyApp == null) {
              String clientSecret = dao.createStudyApp(study, clientId, redirectUri);
              System.out.println("Added study app:\n  Client id: " + clientId + "\n  Client secret: "
                  + clientSecret + "\n  Redirect URI: " + redirectUri);
            } else {
              System.out.println("Client already exists");
            }
          });
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
