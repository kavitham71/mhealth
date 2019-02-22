/*
 * Copyright 2013 The Board of Trustees of The Leland Stanford Junior University.
 * All Rights Reserved.
 *
 * See the NOTICE and LICENSE files distributed with this work for information
 * regarding copyright ownership and licensing. You may not use this file except
 * in compliance with a written license agreement with Stanford University.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See your
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.github.susom.mhealth.server.services;

import com.github.susom.database.Metric;
import java.security.SecureRandom;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generate session keys using the secure random number generator.
 */
public class SessionKeyGenerator {
  private static final Logger log = LoggerFactory.getLogger(SessionKeyGenerator.class);
  private final SecureRandom secureRandom;

  public SessionKeyGenerator(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /**
   * Create a session key with the default length (currently 80 characters).
   */
  public String create() {
    return create(80);
  }

  /**
   * Create a session key of the specified length (in characters).
   */
  public String create(int length) {
    Metric metric = new Metric(log.isDebugEnabled());
    StringBuilder key = new StringBuilder();

    while (key.length() < length) {
      key.append(Long.toString(Math.abs(secureRandom.nextLong()), Character.MAX_RADIX));
    }

    if (log.isDebugEnabled() && metric.elapsedMillis() > 50) {
      log.debug("Session key generation: " + metric.getMessage());
    }

    return key.toString().substring(0, length);
  }

  public static boolean validate(String token) {
    boolean valid = true;
    if (token.length() == 0 || token.length() > 80) {
      valid = false;
    }
    if (!StringUtils.isAlphanumeric(token)) {
      valid = false;
    }
    return valid;
  }

  public static String validated(String token) {
    if (validate(token)) {
      return token;
    }
    throw new SecurityException("Invalid token");
  }
}
