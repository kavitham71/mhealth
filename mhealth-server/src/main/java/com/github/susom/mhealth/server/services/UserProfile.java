package com.github.susom.mhealth.server.services;

public class UserProfile {

  private String name;
  private String username;
  private String email;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String toString() {
    String profile = new String();
    profile =
        "{\"email\" : \"" + this.email + "\"," + "\"firstName\":\"" + this.name + "\"," + "\"username\":\""
            + this.username + "\"," + "\"type\": \"UserProfile\" }";
    return profile;
  }

}
