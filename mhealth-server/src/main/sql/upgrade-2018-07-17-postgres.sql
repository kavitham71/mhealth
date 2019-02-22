alter table rp_genepool_consent 
        ADD COLUMN html_assent text COLLATE pg_catalog.default,        
        ADD COLUMN pdf_assent bytea;

alter table rp_genepool_consent_history 
        ADD COLUMN html_assent text COLLATE pg_catalog.default,        
        ADD COLUMN pdf_assent bytea;
        commit;