/*
 * Copyright (c) 2013 Stanford University SoM, All Rights Reserved.
 */

package com.github.susom.mhealth.server.services;

import com.github.susom.database.Database;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.function.Supplier;
import java.util.logging.Logger;
import org.checkerframework.checker.tainting.qual.Untainted;


/**
 * A report definition that dynamically sets the column order and column
 * data types based off of the {@link ResultSetMetaData} for the sql query.
 * Example usage:
 * <p>
 * <code>
 * ReportDefinition reportDefinition = new DynamicSqlReportGenerator("title", "subtitle", sql, connection);
 * SqlReportQuery reportQuery = reportDefinition.getReportQuery();
 * Report report = reportQuery.execute();
 * ReportRender renderer = new XmlReportRenderer(Styles.DEFAULT_STYLE_FACTORY));
 * MimeContent content = renderer.render(report);
 * </code>
 * </p>
 *
 * @author Ritika Maheshwari
 */
public class DynamicSqlReportGenerator {

  private static final Logger LOG = Logger.getLogger(DynamicSqlReportGenerator.class.getName());

  private int numColumns = 0;
  private final String title;
  private final  @Untainted String sql;
  private final PrintWriter pw;
  private final StringWriter sw;
  private final Supplier<Database> dbs;
  private ArrayList<String> columnLabels;
  private ArrayList<String> columnNames;
  private ArrayList<Integer> columnTypes;

  public DynamicSqlReportGenerator(String title, @Untainted  String sql, Supplier<Database> dbs) {
    this.title = title;
    this.sql =  sql;
    this.dbs = dbs;
    this.sw = new StringWriter();
    this.pw = new PrintWriter(sw);
    initColumnMetaData();
  }

  private void initColumnMetaData() {
        dbs.get().toSelect(sql).query(rs -> {
        ResultSetMetaData rsMetaData = rs.getMetadata();
        numColumns = rsMetaData.getColumnCount();
        columnLabels = getColumnLabels(rsMetaData);
        columnNames = getColumnNames(rsMetaData);
        columnTypes = getColumnTypes(rsMetaData);
         return null;
          });
  }

  public String getTitle() {
    return title;
  }

  protected @Untainted String getSql() {
    return sql;
  }

  public int getNumColumns() {
    return numColumns;
  }

  private ArrayList<String> getColumnLabels(ResultSetMetaData rsMetaData) throws SQLException {
    ArrayList<String> columnLabels = new ArrayList<String>();
    for (int i = 1; i <= numColumns; i++) {
      columnLabels.add(rsMetaData.getColumnLabel(i));
    }
    return columnLabels;
  }

  private ArrayList<String> getColumnNames(ResultSetMetaData rsMetaData) throws SQLException {
    ArrayList<String> columnNames = new ArrayList<String>();
    for (int i = 1; i <= numColumns; i++) {
      columnNames.add(rsMetaData.getColumnName(i));
    }
    return columnNames;
  }

  /**
   * Creates an array of column types that correspond to the
   * {@link Types} types.
   */
  private ArrayList<Integer> getColumnTypes(ResultSetMetaData rsMetaData) throws SQLException {
    ArrayList<Integer> columnTypes = new ArrayList<Integer>();
    for (int i = 1; i <= numColumns; i++) {
      columnTypes.add(rsMetaData.getColumnType(i));
    }
    return columnTypes;
  }

  private int getColumnType(int columnNumber) {
    int columnType = columnTypes.get(columnNumber);
    return columnType;

  }

  @Override
  public String toString() {
    return "DynamicSqlReportGenerator [numColumns=" + numColumns + ", title="
        + title +  ", sql=" + sql + "]";
  }

  public String execute() {
    //do title
    writeTitle(title);
    startTable();
    // do the heading
    startHeaderRow();
    for (int i = 0; i < numColumns; i++) {
      writeHeaderCell(i);
    }
    endHeaderRow();
    startTableBody();
    // do the content
     dbs.get().toSelect(sql).queryMany((rs1) -> {
          startRow();
          for (int i = 0; i < numColumns; i++) {
            switch (columnTypes.get(i)) {
            case Types.BIGINT:
              writeCell(rs1.getBigDecimalOrNull());
              break;
            case Types.INTEGER:
              writeCell(rs1.getIntegerOrNull());
              break;
            case Types.FLOAT:
              writeCell(rs1.getFloatOrNull());
              break;
            case Types.DOUBLE:
              writeCell(rs1.getDoubleOrNull());
              break;
            case Types.VARCHAR:
            case Types.LONGNVARCHAR:
              writeCell(rs1.getStringOrNull());
              break;
            case Types.CLOB:
              writeCell(rs1.getClobStringOrNull());
              break;
            case Types.BOOLEAN:
              writeCell(rs1.getBooleanOrNull());
              break;
            case Types.DATE:
            case Types.TIME:
            case Types.TIMESTAMP:
              writeCell(rs1.getDateOrNull());
              break;
            default:
              writeCell(rs1.getStringOrNull());
            }
          }
         endRow();

        return null;
      });
    //write the cells to printwriter
    endTableBody();
    endTable();
    pw.flush();
    return sw.toString();
  }

  protected void startTable() {
    pw.println("<div class=\"headercontainer\">");
    pw.println("<div class=\"tablecontainer\">");
    pw.println("<table>");
  }

  protected void startHeaderRow() {
   pw.println("<thead>");
   pw.println("<tr>");
  }

  protected void endHeaderRow() {
    pw.println("</thead>");
    pw.println("</tr>");
  }

  protected void endTableBody() {
    pw.println("</tbody>");
  }

  protected void startTableBody() {
    pw.println("<tbody>");
  }

  protected void endTable() {
    pw.println("</table>");
    pw.println("</div>");
    pw.println("</div>");
    pw.println("</div>");
  }

  protected void startRow() {
    pw.println("<tr>");
  }

  protected void endRow() {
    pw.println("</tr>");
  }

  protected void writeHeaderCell(int pos) {
    pw.print("<th>");
    pw.print(columnNames.get(pos));
    pw.print("<div>");
    pw.print(columnNames.get(pos));
    pw.print("</div>");
    pw.println("</th>");
  }

  protected void writeCell( Object value) {
    String val = null;
    val = (value != null ? value.toString() : val);
    pw.print("<td >");
    pw.print(val);
    pw.println("</td>");
  }

protected void writeTitle(String text) {
  pw.println("<div>");
  pw.print("<h3 font-family=\"verdana\" font-size=\"100%\" color=\"blue\">");
  pw.print(text);
  pw.println("</h3>");
}

}