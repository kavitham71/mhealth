alter table rp_genepool_consent 
drop column child_name,
        drop column wear_device,
        drop column mrn,
        ADD COLUMN opt_out character(1) COLLATE pg_catalog.default,
        ADD COLUMN participant_mrn character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN receive_biochemical_tests character(1) COLLATE pg_catalog.default,
        ADD COLUMN submit_urine_sample character(1) COLLATE pg_catalog.default,
        ADD COLUMN assent_child_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN assent_adult_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN child_cannot_assent character(1) COLLATE pg_catalog.default,
        ADD COLUMN participant_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN email_address character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN gender character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN attending_physician_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN adult_participant character(1) COLLATE pg_catalog.default;
        commit;

alter table rp_genepool_consent_history 
        drop column child_name,
        drop column wear_device,
        drop column mrn,
        ADD COLUMN opt_out character(1) COLLATE pg_catalog.default,
        ADD COLUMN participant_mrn character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN receive_biochemical_tests character(1) COLLATE pg_catalog.default,
        ADD COLUMN submit_urine_sample character(1) COLLATE pg_catalog.default,
        ADD COLUMN assent_child_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN assent_adult_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN child_cannot_assent character(1) COLLATE pg_catalog.default,
        ADD COLUMN participant_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN email_address character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN gender character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN attending_physician_name character varying(256) COLLATE pg_catalog.default,
        ADD COLUMN adult_participant character(1) COLLATE pg_catalog.default;
        commit;

        
alter table rp_study
		ADD COLUMN req_email_validation character(1) COLLATE pg_catalog.default;
         commit;       

update rp_study set req_email_validation='Y';
    commit;  
update rp_study set req_email_validation='N' where short_name='genepool';
            commit;


