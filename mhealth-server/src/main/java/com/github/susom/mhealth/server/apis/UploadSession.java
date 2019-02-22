package com.github.susom.mhealth.server.apis;

/**
 * Response returned to the client when they request an upload url.
 */
@SuppressWarnings("unused")
public class UploadSession {
  private String id;
  private String url;
  private String expires;
  private String type;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getExpires() {
    return expires;
  }

  public void setExpires(String expires) {
    this.expires = expires;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}
