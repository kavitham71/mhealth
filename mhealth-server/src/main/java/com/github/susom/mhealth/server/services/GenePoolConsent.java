package com.github.susom.mhealth.server.services;

/**
 * Created by ritikam on 9/27/16.
 */
public class GenePoolConsent {

  private Boolean isAdultParticipant;
  private Boolean shareWithNih;
  private Boolean treatableGeneticFindings;
  private Boolean bothGeneticFindings;
  private Boolean doNotInformGeneticFindings;
  private Boolean relatedToFamilyHistory;
  private String familyHistoryOfDisease;
  private Boolean stanfordResearchRegistry;
  private String htmlConsent;
  private byte[] pdfConsent;
  private Boolean optOut;
  private Boolean receiveBiochemicalTests;
  private Boolean submitUrineSample;
  private String assentChildName;
  private String assentAdultName;
  private Boolean childCannotAssent;
  private String participantName;
  private String emailAddress;
  private String race;
  private String ethnicity;
  private Integer zipCode;
  private String gender;
  private String participantMrn;
  private String attendingPhysicianName;
  private String htmlAssent;
  private byte[] pdfAssent;

  public String getHtmlConsent() {
    return htmlConsent;
  }

  public void setHtmlConsent(String htmlConsent) {
    this.htmlConsent = htmlConsent;
  }

  public byte[] getPdfConsent() {
    return pdfConsent;
  }

  public void setPdfConsent(byte[] pdfConsent) {
    this.pdfConsent = pdfConsent;
  }

  public String getEthnicity() {
    return ethnicity;
  }

  public void setEthnicity(String ethnicity) {
    this.ethnicity = ethnicity;
  }

  public Boolean getAdultParticipant() {
    return isAdultParticipant;
  }

  public void setAdultParticipant(Boolean adultParticipant) {
    isAdultParticipant = adultParticipant;
  }

  public Boolean getShareWithNih() {
    return shareWithNih;
  }

  public void setShareWithNih(Boolean shareWithNih) {
    this.shareWithNih = shareWithNih;
  }

  public Boolean getTreatableGeneticFindings() {
    return treatableGeneticFindings;
  }

  public void setTreatableGeneticFindings(Boolean treatableGeneticFindings) {
    this.treatableGeneticFindings = treatableGeneticFindings;
  }

  public Boolean getBothGeneticFindings() {
    return bothGeneticFindings;
  }

  public void setBothGeneticFindings(Boolean bothGeneticFindings) {
    this.bothGeneticFindings = bothGeneticFindings;
  }

  public Boolean getDoNotInformGeneticFindings() {
    return doNotInformGeneticFindings;
  }

  public void setDoNotInformGeneticFindings(Boolean doNotInformGeneticFindings) {
    this.doNotInformGeneticFindings = doNotInformGeneticFindings;
  }

  public Boolean getRelatedToFamilyHistory() {
    return relatedToFamilyHistory;
  }

  public void setRelatedToFamilyHistory(Boolean relatedToFamilyHistory) {
    this.relatedToFamilyHistory = relatedToFamilyHistory;
  }

  public String getFamilyHistoryOfDisease() {
    return familyHistoryOfDisease;
  }

  public void setFamilyHistoryOfDisease(String familyHistoryOfDisease) {
    this.familyHistoryOfDisease = familyHistoryOfDisease;
  }

  public Boolean getStanfordResearchRegistry() {
    return stanfordResearchRegistry;
  }

  public void setStanfordResearchRegistry(Boolean stanfordResearchRegistry) {
    this.stanfordResearchRegistry = stanfordResearchRegistry;
  }

  public Integer getZipCode() {
    return zipCode;
  }

  public void setZipCode(Integer zipCode) {
    this.zipCode = zipCode;
  }

  public String getRace() {
    return race;
  }

  public void setRace(String race) {
    this.race = race;
  }

  public Boolean getIsAdultParticipant() {
    return isAdultParticipant;
  }

  public void setIsAdultParticipant(Boolean isAdultParticipant) {
    this.isAdultParticipant = isAdultParticipant;
  }

  public Boolean getReceiveBiochemicalTests() {
    return receiveBiochemicalTests;
  }

  public void setReceiveBiochemicalTests(Boolean receiveBiochemicalTests) {
    this.receiveBiochemicalTests = receiveBiochemicalTests;
  }

  public Boolean getSubmitUrineSample() {
    return submitUrineSample;
  }

  public void setSubmitUrineSample(Boolean submitUrineSample) {
    this.submitUrineSample = submitUrineSample;
  }

  public String getAssentChildName() {
    return assentChildName;
  }

  public void setAssentChildName(String assentChildName) {
    this.assentChildName = assentChildName;
  }

  public String getAssentAdultName() {
    return assentAdultName;
  }

  public void setAssentAdultName(String assentAdultName) {
    this.assentAdultName = assentAdultName;
  }

  public Boolean getChildCannotAssent() {
    return childCannotAssent;
  }

  public void setChildCannotAssent(Boolean childCannotAssent) {
    this.childCannotAssent = childCannotAssent;
  }

  public String getParticipantName() {
    return participantName;
  }

  public void setParticipantName(String participantName) {
    this.participantName = participantName;
  }

  public String getEmailAddress() {
    return emailAddress;
  }

  public void setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;
  }

  public String getGender() {
    return gender;
  }

  public void setGender(String gender) {
    this.gender = gender;
  }

  public String getParticipantMrn() {
    return participantMrn;
  }

  public void setParticipantMrn(String participantMrn) {
    this.participantMrn = participantMrn;
  }

  public String getAttendingPhysicianName() {
    return attendingPhysicianName;
  }

  public void setAttendingPhysicianName(String attendingPhysicianName) {
    this.attendingPhysicianName = attendingPhysicianName;
  }

  public Boolean getOptOut() {
    return optOut;
  }

  public void setOptOut(Boolean optOut) {
    this.optOut = optOut;
  }

  public String getHtmlAssent() {
    return htmlAssent;
  }

  public byte[] getPdfAssent() {
    return pdfAssent;
  }

  public void setHtmlAssent(String htmlAssent) {
    this.htmlAssent = htmlAssent;
  }

  public void setPdfAssent(byte[] pdfAssent) {
    this.pdfAssent = pdfAssent;
  }

}
