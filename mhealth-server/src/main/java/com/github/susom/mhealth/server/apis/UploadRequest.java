package com.github.susom.mhealth.server.apis;

/**
 * Data object for a client to request a URL for uploading a data file to the server.
 */
@SuppressWarnings("unused")
public class UploadRequest {
  private String name;
  private Integer contentLength;
  private String contentType;
  private String contentMd5;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Integer getContentLength() {
    return contentLength;
  }

  public void setContentLength(Integer contentLength) {
    this.contentLength = contentLength;
  }

  public String getContentType() {
    return contentType;
  }

  public void setContentType(String contentType) {
    this.contentType = contentType;
  }

  public String getContentMd5() {
    return contentMd5;
  }

  public void setContentMd5(String contentMd5) {
    this.contentMd5 = contentMd5;
  }
}
