package com.github.susom.mhealth.server.apis;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import java.util.Date;

/**
 * This is an interface to 23andme service
 *
 * @author garricko
 */
public interface SageApi {

  void getParticipants(String sageSession, String email, Handler<AsyncResult<StudyParticipant>> handler);

  class StudyParticipant {
    public String study;
    public String email;
    public String password;
    public String firstName;
    public String lastName;
    public String externalId;
    public String sharingScope;
    public Boolean notifyByEmail;
    public String[] dataGroups;
    public String[] languages;
    public Object attributes;
    public String status;
    public String[] roles;
    public Date createdOn;
    public String healthCode;
    public Object[] consentHistories;
    public String id;
    public String type;
  }

}
