package com.github.susom.mhealth.server.apis;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import java.util.List;

/**
 * This is an interface to 23andme service
 *
 * @author garricko
 */
public interface TwentyThreeAndMe {

  void refreshToken(String refreshToken, Handler<AsyncResult<RefreshResult>> handler);

  void userInfo(String accessToken, Handler<AsyncResult<UserResult>> handler);

  void geneticData(String profileId, String accessToken, Handler<AsyncResult<GenomeData>> handler);

  class RefreshResult {
    public String accessToken;
    public String refreshToken;
  }

  class UserResult {
    public String id;
    public List<Profile> profiles;
  }

  class Profile {
    public Boolean genotyped;
    public String id;
  }

  class GenomeData {
    public String id;
    public String genome;
  }
}
