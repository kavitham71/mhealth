package com.github.susom.mhealth.server.services;

import java.util.Date;

public class SchedulePlan {

  private String guid;

  public String getGuid() {
    return guid;
  }

  public void setGuid(String guid) {
    this.guid = guid;
  }

  public String getStudyKey() {
    return studyKey;
  }

  public void setStudyKey(String studyKey) {
    this.studyKey = studyKey;
  }

  public Date getModifiedOn() {
    return modifiedOn;
  }

  public void setModifiedOn(Date modifiedOn) {
    this.modifiedOn = modifiedOn;
  }

  public Double getVersion() {
    return version;
  }

  public void setVersion(Double version) {
    this.version = version;
  }

  public Object getStrategy() {
    return strategy;
  }

  public void setStrategy(Object strategy) {
    this.strategy = strategy;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  private String studyKey;
  private Date modifiedOn;
  private Double version;
  private Object strategy;
  private String type;

}
