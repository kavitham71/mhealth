package com.github.susom.mhealth.server.tools;

import com.github.susom.database.DatabaseProvider;
import com.github.susom.mhealth.server.services.MyPartDao;
import com.github.susom.mhealth.server.services.MyPartDao.Auth;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/**
 * Utility for adding users to the database for testing purposes.
 */
public class AddPortalUser {
  public static void main(String[] args) {
    try {
      DatabaseProvider.fromPropertyFileOrSystemProperties("local.properties").transact(db -> {
        SecureRandom random = new SecureRandom();
        MyPartDao dao = new MyPartDao(db, random);
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        Auth auth = dao.authByEmail("garrick@example.com");

        if (auth == null) {
          auth = new Auth();
          auth.email = "garrick@example.com";
          auth.password = OpenBSDBCrypt.generate("secret".toCharArray(), salt,13);
          auth.usernameNormalized = "garrick";
          auth.usernameDisplay = "Garrick";
          auth.displayName = "Garrick Olson";
          dao.createAuth(auth);
        }
      });
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
