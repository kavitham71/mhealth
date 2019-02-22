package com.github.susom.mhealth.server.tools;

import com.github.susom.database.Config;
import com.github.susom.database.Database;
import com.github.susom.database.DatabaseProvider;
import com.github.susom.database.Flavor;
import com.github.susom.database.Schema;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility to create a database schema for this application.
 */
public class CreateSchema {
  @SuppressWarnings("tainting") // anything we can do, whoever gave us the database credentials can do
  public static void main(String[] args) {
    try {
      Set<String> argSet = new HashSet<>(Arrays.asList(args));
      String propertiesFile = System.getProperty("local.properties", "local.properties");
      Config config = Config.from().systemProperties().propertyFile(propertiesFile).get();
      String databaseUrl = config.getString("database.url");
      if (databaseUrl != null) {
        String databaseUser = config.getString("database.user");
        String databasePassword = config.getString("database.password");

        if (argSet.contains("-recreate")) {
          argSet.remove("-recreate");
          String systemUser = config.getString("database.system.user");
          String systemPassword = config.getString("database.system.password");
          DatabaseProvider.fromDriverManager(databaseUrl, systemUser, systemPassword).transact(dbp -> {
            Database db = dbp.get();
            if (db.flavor() == Flavor.postgresql) {
              // Drop quietly in case it doesn't already exist
              db.ddl("drop owned by " + databaseUser + " cascade").executeQuietly();
              db.ddl("drop user " + databaseUser).executeQuietly();

              db.ddl("create user " + databaseUser + " with password '" + databasePassword + "'").execute();
              db.ddl("create schema authorization " + databaseUser).execute();
              db.ddl("grant all privileges on schema " + databaseUser + " to " + databaseUser).execute();
              db.ddl("grant connect on database " + databaseUrl.substring(databaseUrl.contains("/")
                  ? databaseUrl.lastIndexOf('/') + 1 : databaseUrl.lastIndexOf(':') + 1) + " to "
                  + databaseUser).execute();
            } else if (db.flavor() == Flavor.oracle) {
              // Drop quietly in case it doesn't already exist
              db.ddl("drop user " + databaseUser + " cascade").executeQuietly();

              db.ddl("create user " + databaseUser + " identified by \"" + databasePassword + "\""
                  + " default tablespace users quota unlimited on users temporary tablespace temp").execute();
              db.ddl("grant connect to " + databaseUser).execute();
              db.ddl("grant create table to " + databaseUser).execute();
              db.ddl("grant create trigger to " + databaseUser).execute();
              db.ddl("grant create view to " + databaseUser).execute();
              db.ddl("grant create sequence to " + databaseUser).execute();
              db.ddl("grant create procedure to " + databaseUser).execute();
              db.ddl("grant ctxapp to " + databaseUser).execute();
              db.ddl("grant select any dictionary to " + databaseUser).execute();
            }
          });
        }

        DatabaseProvider.fromDriverManager(databaseUrl, databaseUser, databasePassword).transact(dbp -> {
          // @formatter:off
          if (argSet.contains("mhealth") || argSet.isEmpty()) {
            // The mHealth database, separate from the research portal database below
            new Schema()
              .addTable("mh_scoper")
                .withComment("Generic representation of the context in which we are collecting data, to keep"
                    + " data from different sources properly segregated.")
                .addColumn("mh_scoper_id").primaryKey().table()
                .addColumn("short_name").asString(32).notNull()
                .withComment("Short, lowercase, no spaces (use underscores)").table()
                .addColumn("display_name").asString(80).table()
                .addColumn("description").asString(4000).table()
                .addCheck("mh_scoper_short_name_ck", "short_name=lower(replace(short_name,' ','_'))").table().schema()
              .addTable("mh_file_upload")
                .withComment("Each row in here is an attempt for a client to upload a file. The row is"
                    + " updated if and when the upload is completed.")
                .addColumn("mh_file_upload_id").primaryKey().table()
                .addColumn("mh_scoper_id").asLong().notNull().table()
                .addColumn("mh_upload_sequence").asLong().table()
                .addColumn("mh_device_app_id").asLong().notNull().table()
                .addColumn("upload_token").asString(256).table()
                .addColumn("requested_time").asDate().notNull().table()
                .addColumn("completed_time").asDate().table()
                .addColumn("content_bytes").asLong().table()
                .addColumn("content_md5").asString(32).table()
                .addColumn("device_app_type").asString(80).table()
                .addColumn("device_app_version").asString(80).table()
                .addColumn("device_app_address").asString(160).table()
                .addColumn("device_app_user_agent_id").asLong().table()
                .addForeignKey("mh_file_upload_scoper_fk", "mh_scoper_id").references("mh_scoper").table()
                .addForeignKey("mh_file_upload_device_fk", "mh_device_app_id").references("mh_device_app").table()
                .addForeignKey("mh_file_upload_ua_fk", "device_app_user_agent_id").references("mh_user_agent").table().schema()
              .addTable("mh_file_upload_content")
                .withComment("Table for storing uploaded file contents, one-to-one with file_upload table.")
                .addColumn("mh_file_upload_id").primaryKey().table()
                .addColumn("content_location").asString(4000)
                  .withComment("Support for archiving data elsewhere. Null if the content is here.").table()
                .addColumn("content").asBlob().table()
                .addForeignKey("mh_file_upload_content_fk", "mh_file_upload_id").references("mh_file_upload").table()
                .customTableClause(Flavor.oracle, "lob(content) store as securefile").schema()
              .addTable("mh_user_agent")
                .withComment("Record browser user agent strings, one row per unique string within the scoper")
                .addColumn("mh_user_agent_id").primaryKey().table()
                .addColumn("mh_scoper_id").asLong().notNull().table()
                .addColumn("user_agent_md5").asString(32).notNull().table()
                .addColumn("user_agent_str").asClob().notNull().table()
                .addForeignKey("mh_user_agent_scoper_fk", "mh_scoper_id").references("mh_scoper").table()
                .addUnique("mh_user_agent_scoper_md5_uq", "mh_scoper_id", "user_agent_md5").table()
                .customTableClause(Flavor.oracle, "lob(user_agent_str) store as securefile").schema().addSequence("mh_user_agent_id_pk_seq").schema()
              .addTable("mh_device_app")
                .addColumn("mh_device_app_id").primaryKey().table()
                .addColumn("mh_scoper_id").asLong().notNull().table()
                .addColumn("mh_user_profile_id").asLong().table()
                .addColumn("app_key_type").asString(32).table()
                .addColumn("app_key").asString(120).table()
                .addColumn("device_rpid").asString(120).table()
//              .addColumn("display_name").asString(120).table()
//              .addColumn("enabled").asBoolean().table()
                .addIndex("mh_device_app_key_uq", "app_key", "app_key_type").unique().table()
                .addIndex("mh_device_app_rpid_uq", "device_rpid").unique().table()
                .addForeignKey("mh_device_app_scoper_fk", "mh_scoper_id").references("mh_scoper").table()
                .addForeignKey("mh_device_app_profile_fk", "mh_user_profile_id").references("mh_user_profile").table().schema()
              .addTable("mh_access_token")
                 .withHistoryTable()
                 .trackUpdateTime() 
                 .addColumn("uncrypted_token").primaryKey().asString(200).notNull()
                 .withComment("The first half of the random key which is not bcrypted").table()
                 .addColumn("bcrypted_token").asString(200).notNull()
                 .withComment("The other half of the random key which is bcrypted").table()
                 .addColumn("sunet_id").asString(200).notNull().table()
                 .addColumn("study_id").asLong().notNull().table()
                 .addColumn("org_id").asLong().notNull().table()
                 .addColumn("valid_from").asDate().notNull().table()
                 .addColumn("valid_thru").asDate().notNull().table().schema()               
              .addTable("mh_user_profile")
                .addColumn("mh_user_profile_id").primaryKey().table()
                .addColumn("mh_scoper_id").notNull().foreignKey("mh_user_profile_scoper_fk").references("mh_scoper").table()
                .addColumn("user_rpid").asLong()
                .withComment("Identifier for a research participant, externally assigned by the research"
                    + " portal, and unique within the mHealth application and scoper_id.").schema()
                .addTable("mh_invalid_session_token")
                 .withComment("Contains the invalid session token for mhealth server")
                 .trackUpdateTime()
                .addColumn("mh_session_token").asClob().notNull().table().schema()
                .addSequence("mh_upload_seq").schema()  
                .addSequence("mh_pk_seq").schema().execute(dbp.get());
              // Other demographics or user attributes as needed, de-identified
              // service_login table

            dbp.get().toInsert("insert into mh_scoper (mh_scoper_id, short_name, display_name) values (?,?,?)")
                .argInteger(100).argString("cardiovascular").argString("MyHeart Counts").insert(1);
            dbp.get().toInsert("insert into mh_scoper (mh_scoper_id, short_name, display_name) values (?,?,?)")
            .argInteger(200).argString("genepool").argString("GenePool Study").insert(1);
            dbp.get().toInsert("insert into mh_scoper (mh_scoper_id, short_name, display_name) values (?,?,?)")
              .argInteger(203).argString("stopwatch").argString("StopWatch Study").insert(1);
            dbp.get().toInsert("insert into mh_scoper (mh_scoper_id, short_name, display_name) values (?,?,?)")
              .argInteger(204).argString("stream").argString("STREAM Study").insert(1);
          }

          if (argSet.contains("23andme") || argSet.isEmpty()) {
            // The mHealth database, separate from the research portal database below
            new Schema()
                .addTable("tm_user_info")
                  .addColumn("user_id").asString(100).table()
                  .addColumn("profile_id").asString(100).table()
                  .addColumn("bearer_token").asString(100).table()
                  .addColumn("refresh_token").asString(100).table()
                  .addColumn("token_refresh_date").asDate().table()
                  .addColumn("status_key").asString(100).unique("tm_ui_status_key_ix")
                    .withComment("Unique token we provide to the client so they can "
                        + "check download status later").table()
                  .addColumn("genotype_date").asDate().withComment("Timestamp of our last "
                        + "call to the /user API to retrieve information about the user and "
                        + "whether they have been genotyped yet").table()
                  .addColumn("times_get_genotyped_called").asInteger().withComment("The number of times "
                        + "we have called the /user API, regardless of success or failure").table()
                  .addColumn("genotyped").asBoolean().withComment("Flag to indicate whether "
                        + "23andMe has genome information for this user id + profile id").table()
                  .addColumn("genome_date").asDate().withComment("Timestamp of our last "
                        + "call to the /genome API to retrieve their genetic markers").table()
                  .addColumn("times_genome_data_called").asInteger().withComment("The number of times "
                        + "we have called the /genome API, regardless of success of failure").table()
                  .addColumn("pending_error_code").asInteger().withComment("Typically 500, or a specific error "
                        + "code from the 23andMe API. This colulmn is used when the error is something we "
                        + "will handle or retry internally, so the client just sees things as pending").table()
                  .addColumn("pending_error_msg").asString(500).withComment("This message will be returned to "
                        + "the client when they request status via our API").table()
                  .addColumn("download_error_code").asInteger().withComment("Null unless an error occurs that "
                        + "we cannot handle. Once a value is in here, we will report the status as failed "
                        + "when the client requests status via our API. This will take precedence over "
                        + "the pending value.").table()
                  .addColumn("download_error_msg").asString(500).withComment("This message will be returned to "
                        + "the client when they request status via our API. This will take precedence over "
                        + "the pending value.").table()
                  .addColumn("create_date").asDate().withComment("The date when account was created.Null unless the date is set").table()
                  .addColumn("download_status").asBoolean().withComment("Flag indicating whether there is "
                        + "a row in tm_download for this genome. Indicates overall success (or not) for getting the "
                        + "data we desired from 23andMe.").table()
                  .addPrimaryKey("tm_user_info_pk", "user_id", "profile_id").table().schema()
                .addTable("tm_download")
                  .addColumn("user_id").asString(100).table()
                  .addColumn("profile_id").asString(100).table()
                  .addColumn("genetic_data").asClob().withComment("The genome information we intended to "
                        + "get from 23andMe").table()
                  .addPrimaryKey("tm_download_pk", "user_id", "profile_id").table()
                  .addForeignKey("tm_download_fk", "user_id", "profile_id").references("tm_user_info").table()
                  .schema()
                .execute(dbp.get());
          }

          if (argSet.contains("mypart") || argSet.isEmpty()) {
            // The research portal database
            new Schema()
              // History tables, hidden/deleted flags/reasons on everything
              .addTable("rp_device_register_request")
                .addColumn("device_rpid").asString(256).primaryKey().table()
                .addColumn("device_description").asString(4000).table()
                .addColumn("email_recipient").asString(4000).notNull().table()
                .addColumn("email_token").asString(256).notNull().table()
                .addColumn("email_create_time").asDate().notNull().table()
                .addColumn("email_send_time").asDate().table()
                .addColumn("rp_study_id").asLong().table()
                .addColumn("email_successful").asBoolean().table()
//                .addColumn("email_verify_time").asDate().table()
                // email_verify_addr, email_verify_user_agent?
                .addIndex("rp_dev_reg_req_token_uq", "email_token").unique().table().schema()
              .addTable("rp_signup_request")
                .addColumn("email_token").asString(256).primaryKey().table()
                .addColumn("email_recipient").asString(4000).notNull().table()
                .addColumn("email_create_time").asDate().notNull().table()
                .addColumn("email_send_time").asDate().table()
                .addColumn("email_successful").asBoolean().table()
                .addColumn("verify_time").asDate().table()
//                .addColumn("verify_successful").asBoolean().table()
                .addColumn("password_reset_token").asString(256).table()
                .addColumn("password_reset_time").asDate().table()
                // keep track of client_id, scope, and state (so we can pick up where they left off)?
                // email_send_addr, email_send_user_agent?
                // email_verify_addr, email_verify_user_agent?
                .addIndex("rp_signup_pw_tok_ix", "password_reset_token").unique().table()
                .addIndex("rp_signup_email_ix", "email_recipient").table().schema()
              .addTable("rp_consent")
                .withHistoryTable()
                .trackUpdateTime()
                .addColumn("rp_study_id").asLong().notNull().table()
                .addColumn("device_rpid").asString(256).notNull().table()
                .addColumn("name").asString(120).table()
                .addColumn("agreed_time").asDate().table()
                .addColumn("date_of_birth").asDate().table()
                .addColumn("data_sharing_scope").asString(120).table()
                .addColumn("template_name").asString(80).table()
                .addColumn("template_version").asString(80).table()
                .addColumn("html_consent").asClob().table()
                .addColumn("pdf_consent").asBlob().table()
                .addPrimaryKey("rp_consent_pk", "device_rpid").table()
                .addForeignKey("rp_consent_fk1","device_rpid").references("rp_user_device").table()
                .addForeignKey("rp_consent_fk2","rp_study_id").references("rp_study").table().schema()
                // History table? Keep only the current one in here?
                //.addForeignKey("mh_consent_scoper_fk", "mh_scoper_id").references("mh_scoper").table()
                //.addForeignKey("mh_consent_profile_fk", "mh_user_profile_id").references("mh_user_profile").table().schema()
                // .addSequence("mh_pk_seq").schema()
               .addTable("rp_genepool_consent")
                 .withHistoryTable()
                 .trackUpdateTime()
                 .addColumn("rp_study_id").asLong().notNull().table()
                 .addColumn("device_rpid").asString(256).notNull().table()
                 .addColumn("race").asString(256).table()                       //existing
                 .addColumn("ethnicity").asString(256).table()
                 .addColumn("zip_code").asInteger().table()
                 .addColumn("share_with_nih").asBoolean().table()
                 .addColumn("treatable_genetic_findings").asBoolean().table()
                 .addColumn("do_not_inform_genetic_findings").asBoolean().table()
                 .addColumn("related_to_family_history").asBoolean().table()
                 .addColumn("both_genetic_findings").asBoolean().table()
                 .addColumn("family_history_of_disease").asString(256).table()
                 .addColumn("stanford_research_registry").asBoolean().table()

                  .addColumn("receive_biochemical_tests").asBoolean().table()   //newly add
                  .addColumn("submit_urine_sample").asBoolean().table()
                  .addColumn("assent_child_name").asString(256).table()
                  .addColumn("assent_adult_name").asString(256).table()
                  .addColumn("child_cannot_assent").asBoolean().table()
                  .addColumn("participant_name").asString(256).table()
                  .addColumn("email_address").asString(256).table()
                  .addColumn("gender").asString(256).table()
                  .addColumn("participant_mrn").asString(256).table()
                  .addColumn("attending_physician_name").asString(256).table()
                  .addColumn("opt_out").asBoolean().table()
                 .addColumn("adult_participant").asBoolean().table()
                .addColumn("html_assent").asClob().table()
                .addColumn("pdf_assent").asBlob().table()

                 .addPrimaryKey("rp_genepool_consent_pk", "device_rpid").table()
                 .addForeignKey("rp_genepool_consent_fk1","device_rpid").references("rp_consent").table()
                 .addForeignKey("rp_genepool_consent_fk2","rp_study_id").references("rp_study").table().schema()
                .addTable("rp_user")
                .addColumn("rp_user_id").asLong().primaryKey().table()
                .addColumn("account_id").asString(120).table().schema()
//                .addColumn("primary_email_id").asLong().table()
                // name, dob, gender, etc.
//                .addForeignKey("rp_user_email_fk", "primary_email_id").references("rp_user_email").table().schema()
              .addTable("rp_user_device")
                .addColumn("device_rpid").asString(256).primaryKey().table()
                .addColumn("rp_user_id").asLong().notNull().table()
                .addColumn("enabled").asBoolean().notNull().table()
                .addForeignKey("rp_user_device_user_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_user_credential")
                .addColumn("rp_user_id").primaryKey().table()
                // Who issued this credential: mypart, sunet, shc, lpch, etc.
                .addColumn("issuer").asString(120).table()
                // Username, normalized for comparison purposes (e.g. lowercase, with domain suffix)
                .addColumn("username_normalized").asString(120).table()
                // Username, as it is displayed by the issuer (e.g. some hospital SIDs have lowercase s123
                // and some have upper S123)
                .addColumn("username_display").asString(120).table()
                // How the value in the password field should be interpreted (e.g. 'bcrypt')
                .addColumn("password_type").asString(32).table()
                // The password, if we are managing it (could be managed externally depending on issuer)
                .addColumn("password").asString(120).table()
                .addIndex("rp_user_cred_uq", "issuer", "username_normalized").unique().table()
                .addForeignKey("rp_user_credential_user_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_user_email")
                .addColumn("rp_user_email_id").primaryKey().table()
                .addColumn("rp_user_id").asLong().notNull().table()
                .addColumn("email_address").asString(120).table()
                .addColumn("is_primary").asBoolean().notNull().table()
                .addColumn("verify_complete_time").asDate().table()
                .addIndex("rp_user_email_uq", "email_address").unique().table()
                .addForeignKey("rp_user_email_user_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_temporary_auth_code")
                .addColumn("code").asString(256).primaryKey().table()
                .addColumn("create_time").asDate().table()
                .addColumn("expire_time").asDate().table()
                .addColumn("client_id").asString(256).table()
                .addColumn("scope").asString(256).table()
                .addColumn("rp_user_id").asLong().table()
                .addForeignKey("rp_temp_auth_to_cred_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_study")
                .addColumn("rp_study_id").primaryKey().table()
                .addColumn("rp_study_email_subject").asString(200).notNull()
                  .withComment("The subject line for verification email").table()
                .addColumn("rp_study_support_email").asString(150).notNull() 
                  .withComment("The study support email address").table()
                .addColumn("rp_study_sponsor_name").asString(150).notNull() 
                  .withComment("The name for the sponsor of the study").table()  
                .addColumn("short_name").asString(32).notNull()
                  .withComment("Short, lowercase, no spaces (use underscores)").table()
                .addColumn("req_email_validation").asBoolean().notNull()
                  .withComment("Short, lowercase, no spaces (use underscores)").table()
                .addColumn("display_name").asString(80).table()
                .addColumn("description").asString(4000).table()
                .addCheck("rp_study_short_name_ck", "short_name=lower(replace(short_name,' ','_'))").table().schema()
                // PI, IRB #, who to contact, ...
              .addTable("rp_study_app")
                .addColumn("rp_study_app_id").primaryKey().table()
                .addColumn("rp_study_id").asLong().notNull().table()
                .addColumn("client_id").asString(256).table()
                .addColumn("client_secret").asString(256).table()
                // TODO additional value & timestamps to allow rotation
                .addColumn("redirect_uri").asString(4000).table()
                .addIndex("rp_s_app_client_uq", "client_id").unique().table()
                .addForeignKey("rp_s_app_study_fk", "rp_study_id").references("rp_study").table().schema()
              .addTable("rp_user_in_study")
                .withHistoryTable()
                .trackUpdateTime()
                .addColumn("user_rpid").primaryKey().table()
                .addColumn("participation_status").asBoolean().notNull().table()
                .addColumn("enrollment_time").asDate().table()
                .addColumn("rp_user_id").asLong().notNull().table()
                .addColumn("rp_study_id").asLong().notNull().table()
//                .addColumn("context").asString(80).table()
                .addColumn("opaque_user_number").asString(80).table()
                .addForeignKey("rp_u_in_s_user_fk", "rp_user_id").references("rp_user").table()
                .addForeignKey("rp_u_in_s_study_fk", "rp_study_id").references("rp_study").table().schema()
/*
              .addTable("rp_message")
                .addColumn("rp_message_id").primaryKey().table()
                .addColumn("rp_study_id").asLong().table()
                .addColumn("rp_user_id").asLong().notNull().table()
                .addColumn("sent_time").asDate().table()
                .addColumn("subject").asString(4000).table()
                // Maybe these two should go away; just a flag for emailable?
                .addColumn("emailable_summary").asString(4000)
                  .withComment("Non-sensitive message summary, for example, text included in an email.").table()
                .addColumn("secure_summary").asString(4000)
                  .withComment("Possibly sensitive message summary, displayed after user authenticates."
                      + " Null to use the value from emailable_summary.").table()
                .addForeignKey("rp_message_study_fk", "rp_study_id").references("rp_study").table()
                .addForeignKey("rp_message_user_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_message_content")
                .addColumn("rp_message_id").primaryKey().table()
                .addColumn("rp_message_text").asClob().table()
                .addColumn("rp_message_html").asClob().table()
                .addForeignKey("rp_message_content_fk", "rp_message_id").references("rp_message").table().schema()
              .addTable("rp_message_attachment")
                .addColumn("rp_message_attachment_id").primaryKey().table()
                .addColumn("rp_message_id").asLong().notNull().table()
                .addColumn("content").asBlob().table()
                .addForeignKey("rp_message_attachment_fk", "rp_message_id").references("rp_message").table().schema()
              .addTable("rp_email_address")
                .withComment("Write-once archive of email addresses we have used to send emails.")
                .addColumn("rp_email_address_id").primaryKey().table()
                .addColumn("address_full").asString(4000)
                  .withComment("The address to use, e.g. \"XYZ <xyz@example.com>\". Unique in this table.").table()
                .addColumn("address_simple").asString(4000)
                  .withComment("The short address, e.g. \"xyz@example.com\". Not unique in this table.").table()
                .addIndex("rp_email_address_uq", "address_full").unique().table().schema()
              .addTable("rp_email_log")
                .withComment("Write-once archive of emails we have attempted to send.")
                .addColumn("rp_email_log_id").primaryKey().table()
                .addColumn("rp_message_id").asLong().table()
                // Token and content in case this is generic "you have a message waiting...click here"?
                .addColumn("send_start_time").asDate().table()
                .addColumn("send_finish_time").asDate().table()
                .addColumn("send_successful").asBoolean().table()
//                .addColumn("status_message").asString(4000).table()
                .addForeignKey("rp_email_log_message_fk", "rp_message_id").references("rp_message").table().schema()
              .addTable("rp_email_address_log")
                .addColumn("rp_email_log_id").asLong().table()
                .addColumn("rp_email_address_id").asLong().table()
                .addColumn("address_type").asString(3).withComment("Values: from, reply, to, cc, bcc").table()
                .addCheck("rp_email_address_log_type_ck", "address_type in ('from','reply','to','cc','bcc')").table()
                .addForeignKey("rp_email_a_l_e_l_fk", "rp_email_log_id").references("rp_email_log").table()
                .addForeignKey("rp_email_a_l_e_a_fk", "rp_email_address_id").references("rp_email_address").table()
                .addPrimaryKey("rp_email_address_log_pk", "rp_email_log_id", "rp_email_address_id",
                    "address_type").table().schema()
*/
              .addTable("rp_user_sage_info")
                .withComment("Contains the user sage information, which is obtained by calling the participant/self endpoint on sage")
                .addColumn("device_rpid").asString(256).table()
                .addColumn("rp_user_id").asLong().notNull().table()
                .addColumn("email").asString(4000).table()
                .addColumn("status").asString(40).table()
                .addColumn("rp_study_id").asLong().notNull().table()
                .addColumn("id").asString(256).table()
                .addColumn("createdOn").asDate().table()
                .addPrimaryKey("rp_user_sage_info_pk", "device_rpid","rp_user_id").table()
                .addForeignKey("rp_user_sage_1_fk", "device_rpid").references("rp_user_device").table()
                .addForeignKey("rp_user_sage_2_fk", "rp_user_id").references("rp_user").table().schema()
              .addTable("rp_data_sharing_org")
                 .withComment("The details of organisations that will use the mHealth data")
                 .addColumn("rp_org_id").primaryKey().table()
                 .addColumn("short_name").asString(50).table()
                 .addColumn("description").asString(256).table().schema()
              .addTable("rp_researcher_data_access")
                  .withComment("The mapping table showing the studies that a sunetId has access to. Also the organization that the )"
                      + "sunetId belongs to")
                  .addColumn("rp_sunet_id").asString(50).notNull().table()
                  .addColumn("rp_study_id").asLong().notNull().table()
                  .addColumn("rp_org_id").asLong().notNull().table()
                  .addColumn("rp_data_sharing_scope").asString(50).notNull().table()
                  .addPrimaryKey("rp_researcher_data_access_pk", "rp_sunet_id","rp_study_id").table()
                  .addForeignKey("rp_researcher_1_fk", "rp_org_id").references("rp_data_sharing_org").table().schema()
                .addTable("rp_genepool_admin")
                  .withComment("The mapping table showing the sunetId that has access to genepool admin page ")
                  .addColumn("rp_sunet_id").asString(50).notNull().table()
                  .addColumn("rp_study_id").asLong().notNull().table()
                  .addColumn("rp_org_id").asLong().notNull().table()
                  .addPrimaryKey("rp_admin_data_access_pk", "rp_sunet_id","rp_study_id").table()
                  .addForeignKey("rp_admin_1_fk", "rp_org_id").references("rp_data_sharing_org").table().schema()
              .addTable("rp_api_token")
                .withComment("Contains the current valid API token (refresh token). The older tokens are"
                    + " only maintained in history table.")
                .withStandardPk()
                .withHistoryTable()
                .trackUpdateTime()
                .addColumn("rp_sunet_id").asString(50).notNull().table()
                .addColumn("rp_study_id").asLong().notNull().table()
                .addColumn("rp_org_id").asLong().notNull().table()
                .addColumn("uncrypted_token").asString(200).notNull()
                  .withComment("The first half of the random key which is not bcrypted").table()
                .addColumn("bcrypted_token").asString(200).notNull()
                  .withComment("The other half of the random key which is bcrypted").table()
                .addColumn("valid_from").asDate().table()
                .addColumn("valid_thru").asDate().table()
                .addForeignKey("rp_api_token_1_fk", "rp_sunet_id","rp_study_id").references("rp_researcher_data_access").table().schema()
                .addSequence("rp_pk_seq").start(1000).schema().execute(dbp.get()); // shard the sequence?
              // Tables for session info?
            // @formatter:on
            dbp.get().toInsert("insert into rp_data_sharing_org(rp_org_id,short_name,description) values (?,?,?)")
                .argLong(1L)
                .argString("Stanford")
                .argString("Stanford School of Medicine and researchers").insert(1);
            dbp.get().toInsert("insert into rp_data_sharing_org(rp_org_id,short_name,description) values (?,?,?)")
                .argLong(2L)
                .argString("Oxford")
                .argString("Oxford Researchers").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("testing1")
                .argLong(1L)
                .argLong(300L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("garricko")
                .argLong(1L)
                .argLong(300L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("dwaggott")
                .argLong(1L)
                .argLong(300L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("annashch")
                .argLong(1L)
                .argLong(300L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("garricko")
                .argLong(1L)
                .argLong(400L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("garricko")
                .argLong(1L)
                .argLong(500L).argString("sponsors_and_partners").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_genepool_admin(rp_sunet_id,rp_org_id,rp_study_id) values (?,?,?)")
                .argString("apavlovi")
                .argLong(1L)
                .argLong(400L).insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_genepool_admin(rp_sunet_id,rp_org_id,rp_study_id) values (?,?,?)")
                .argString("garricko")
                .argLong(1L)
                .argLong(400L).insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_researcher_data_access(rp_sunet_id,rp_org_id,rp_study_id,rp_data_sharing_scope) values (?,?,?,?)")
                .argString("testing2")
                .argLong(1L)
                .argLong(300L).argString("all_qualified_researchers").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_study(rp_study_id,short_name,display_name,rp_study_email_subject,rp_study_support_email,rp_study_sponsor_name,req_email_validation) values (?,?,?,?,?,?,?)")
                .argLong(300L)
                .argString("cardiovascular").argString("MyHeart Counts")
                .argString("Consent Agreement for MyHeart Counts")
                .argString("MyHeart Counts <myheartcounts-support@stanford.edu>")
                .argString("Stanford Medicine")
                .argString("Y").insert(1);

            dbp.get()
                .toInsert(
                    "insert into rp_study(rp_study_id,short_name,display_name,rp_study_email_subject,rp_study_support_email,rp_study_sponsor_name,req_email_validation) values (?,?,?,?,?,?,?)")
                .argLong(400L)
                .argString("genepool").argString("GenePool")
                .argString("Consent Agreement for GenePool Study")
                .argString("GenePool<genepool-support@stanford.edu>")
                .argString("Stanford Medicine").argString("N").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_study(rp_study_id,short_name,display_name,rp_study_email_subject,rp_study_support_email,rp_study_sponsor_name,req_email_validation) values (?,?,?,?,?,?,?)")
                .argLong(403L)
                .argString("stopwatch").argString("StopWatch")
                .argString("Consent Agreement for StopWatch Study")
                .argString("StopWatch <stopwatch@stanford.edu>")
                .argString("Stanford Medicine").argString("Y").insert(1);
            dbp.get()
                .toInsert(
                    "insert into rp_study(rp_study_id,short_name,display_name,rp_study_email_subject,rp_study_support_email,rp_study_sponsor_name,req_email_validation) values (?,?,?,?,?,?,?)")
                .argLong(404L)
                .argString("stream").argString("STREAM")
                .argString("Consent Agreement for Studying TRiggers in Everyday Activity for Migraine Study")
                .argString("stream-migraine-study@stanford.edu")
                .argString("Stanford Medicine").argString("Y").insert(1);
          }
        });
        System.exit(0);
      } else {
        System.err.println("Set -Ddatabase.[url,system.user,system.password,user,password]=... or -Dlocal.properties=...");
        System.exit(1);
      }
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
