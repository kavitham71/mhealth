package com.github.susom.mhealth.server.services;

/**
 * Data object representing an installed MyHeart Counts iOS App.
 */
@SuppressWarnings("unused")
public class DeviceApp {
  private String appKey;
  private String appKeyType;
  private String deviceRpid;

  public String getAppKey() {
    return appKey;
  }

  public void setAppKey(String appKey) {
    this.appKey = appKey;
  }

  public String getAppKeyType() {
    return appKeyType;
  }

  public void setAppKeyType(String appKeyType) {
    this.appKeyType = appKeyType;
  }

  public String getDeviceRpid() {
    return deviceRpid;
  }

  public void setDeviceRpid(String deviceRpid) {
    this.deviceRpid = deviceRpid;
  }
}
