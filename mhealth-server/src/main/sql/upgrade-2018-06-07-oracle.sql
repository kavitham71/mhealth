ALTER TABLE rp_genepool_consent 
DROP (CHILD_NAME, 
      WEAR_DEVICE, 
      MRN);
      
ALTER TABLE rp_genepool_consent 
ADD (OPT_OUT CHAR(1), 
     PARTICIPANT_MRN VARCHAR2(256), 
     RECEIVE_BIOCHEMICAL_TESTS CHAR(1),
     submit_urine_sample CHAR(1),
     assent_child_name VARCHAR2(256),
     assent_adult_name VARCHAR2(256),
     child_cannot_assent CHAR(1),
     participant_name VARCHAR2(256),
     email_address VARCHAR2(256),
     gender VARCHAR2(256),
     attending_physician_name VARCHAR2(256),
     adult_participant CHAR(1));

ALTER TABLE rp_genepool_consent_history 
DROP (CHILD_NAME, 
      WEAR_DEVICE, 
      MRN);
      
ALTER TABLE rp_genepool_consent_history 
ADD (OPT_OUT CHAR(1), 
     PARTICIPANT_MRN VARCHAR2(256), 
     RECEIVE_BIOCHEMICAL_TESTS CHAR(1),
     submit_urine_sample CHAR(1),
     assent_child_name VARCHAR2(256),
     assent_adult_name VARCHAR2(256),
     child_cannot_assent CHAR(1),
     participant_name VARCHAR2(256),
     email_address VARCHAR2(256),
     gender VARCHAR2(256),
     attending_physician_name VARCHAR2(256),
     adult_participant CHAR(1));
     
alter table rp_study
ADD req_email_validation CHAR(1) default 'Y';
    
update rp_study set req_email_validation='N' where short_name='genepool';
            


