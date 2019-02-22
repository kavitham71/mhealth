alter table rp_genepool_consent
  ADD(html_assent CLOB,
      pdf_assent BLOB);

alter table rp_genepool_consent_history
  ADD(html_assent CLOB,
      pdf_assent BLOB);