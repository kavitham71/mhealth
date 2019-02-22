package com.github.susom.mhealth.server.services;

import java.util.Date;

public class Consent {

  private String name;
  private String scope;
  private Date birthDate;
  private Date agreedTime;
  private String htmlConsent;
  private byte[] pdfConsent;
  private String email;
  private Long studyId;
  private String signingDate;
  private Integer useruserId;
  private Long updateSequence;

  public Long getUpdateSequence() {
    return updateSequence;
  }

  public void setUpdateSequence(Long updateSequence) {
    this.updateSequence = updateSequence;
  }

  public Long getStudyId() {
    return studyId;
  }

  public Date getAgreedTime() {
    return agreedTime;
  }

  public void setAgreedTime(Date agreedTime) {
    this.agreedTime = agreedTime;
  }

  public void setStudyId(Long studyId) {
    this.studyId = studyId;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public byte[] getPdfConsent() {
    return pdfConsent;
  }

  public void setPdfConsent(byte[] pdfConsent) {
    this.pdfConsent = pdfConsent;
  }

  public String getSigningDate() {
    return signingDate;
  }

  public void setSigningDate(String signingDate) {
    this.signingDate = signingDate;
  }

  public Integer getUserId() {
    return useruserId;
  }

  public void setUseruserId(Integer useruserId) {
    this.useruserId = useruserId;
  }

  public String getHtmlConsent() {
    return htmlConsent;
  }

  public void setHtmlConsent(String consent) {
    htmlConsent = consent;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getScope() {
    return scope;
  }

  public void setScope(String scope) {
    this.scope = scope;
  }

  public Date getBirthDate() {
    return birthDate;
  }

  public void setBirthDate(Date birthDate) {
    this.birthDate = birthDate;
  }

}
