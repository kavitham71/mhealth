package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMe;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import io.vertx.core.Vertx;

/**
 * Utility to manually test the component that interacts with the 23andMe API.
 *
 * @author garricko
 */
public class TwentyThreeAndMeRealTester {
  public static void main(String[] args) {
    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    Vertx vertx = Vertx.vertx();

//    String propertiesFile = System.getProperty("local.properties", "../local.properties");
//    Config config = Config.from().systemProperties().propertyFile(propertiesFile).get();

    Config config = Config.from()
        .value("23andme.client.id", "f57c18559c58d802fe3b32a52ab0b08c")
        .value("23andme.client.secret", "c14a4dea945c1ce756d351fc74013b12")
        .value("23andme.client.uri", "http://localhost:5000/receive_code/").get();

    TwentyThreeAndMe twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);

    twentyThreeAndMe.refreshToken("6282d06e2a936a8066550907aae9a2a1", result -> {
      if (result.succeeded()) {
        System.out.println("Access token: " + result.result().accessToken);
        System.out.println("Refresh token: " + result.result().refreshToken);
      } else {
        result.cause().printStackTrace();
      }
    });
    twentyThreeAndMe.userInfo("36751968fafdc5e1d13fb79b8ff36b46", result -> {
      if (result.succeeded()) {
        System.out.println("Profile id: " + result.result().id);
        System.out.println("Profiles size: " + result.result().profiles.size());
      } else {
        result.cause().printStackTrace();
      }
    });
    twentyThreeAndMe.geneticData("SP1_MOTHER_V4", "36751968fafdc5e1d13fb79b8ff36b46", result -> {
      if (result.succeeded()) {
        System.out.println("Genome: " + result.result().genome);
        System.out.println("Profile id: " + result.result().id);
      } else {
        result.cause().printStackTrace();
      }
    });
  }
}
