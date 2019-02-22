alter table rp_genepool_consent
  ADD COLUMN html_assent CLOB,
  ADD COLUMN pdf_assent BLOB;

alter table rp_genepool_consent_history
  ADD COLUMN html_assent CLOB,
  ADD COLUMN pdf_assent BLOB;
commit;