package com.github.susom.mhealth.server.services;

import java.util.Map;

public class Util {

  public static String resolveHtmlTemplate(String template, Map<String, String> values) {

    for (Map.Entry<String, String> entry : values.entrySet()) {
      if (entry.getValue() != null) {
        String var = "${" + entry.getKey() + "}";
        template = template.replace(var, entry.getValue());
      }
    }
    return template;
  }

}
