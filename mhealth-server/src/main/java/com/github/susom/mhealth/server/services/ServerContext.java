package com.github.susom.mhealth.server.services;

/**
 * Functionality that is available per logical "server". Note this does not mean
 * there is any guarantee about how many instances there are in the JVM.
 */
public interface ServerContext {
  Mailer mailer();

//  UserInfo userInfo();

//  DatasourceInfo datasourceInfo();

//  LdapInfo ldapInfo();

//  IdGenerator idGenerator();

//  AsyncQuery asyncQuery();
}
