package com.github.susom.mhealth.server.tools;

import com.github.susom.database.DatabaseProvider;
import java.io.File;
import org.apache.commons.io.FileUtils;

/**
 * Pull any downloaded 23andMe genomes out of the database, place
 * them in local files, and create a .tar.gz for them.
 */
public class ExportGenomes {
  public static void main(String[] args) {
    try {
      // Where to put the extracted data - look for name-*.tar.gz in path after running
      String path = "target/";
      String name = "23andme-data-prod";
      // First day to export, inclusive
      String from = "2016-03-24";
      // Last day to export, inclusive - make sure it is in the past so the daily data is complete
      String thru = "2016-05-17";

      DatabaseProvider.fromSystemProperties().transact(db -> {
        db.get().toSelect("select to_char(genome_date,'YYYY-MM-DD') genome_date, d.user_id, d.profile_id, genetic_data"
            + " from tm_download d join tm_user_info ui on d.user_id=ui.user_id and d.profile_id=ui.profile_id"
            + " where genome_date >= to_date(?,'YYYY-MM-DD')"
            + " and genome_date < to_date(?,'YYYY-MM-DD')+1 order by 1")
            .argString(from).argString(thru).queryMany(r -> {
          String date = r.getStringOrEmpty();
          String userId = r.getStringOrEmpty();
          String profileId = r.getStringOrEmpty();
          String genome = r.getStringOrEmpty();

          File directory = new File(path + name + "/" + date + "/");
          FileUtils.forceMkdir(directory);
          FileUtils.writeStringToFile(new File(directory, userId + "-" + profileId + ".txt"), genome,"utf-8");

          return null;
        });
      });

      Runtime.getRuntime().exec("tar czf " + name + "-" + from + "-thru-" + thru + ".tar.gz " + name,
          null, new File(path));
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
