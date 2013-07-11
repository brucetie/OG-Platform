/**
 * Copyright (C) 2009 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.examples.bloomberg.tool;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.ClassUtils;

import com.opengamma.integration.tool.IntegrationToolContext;
import com.opengamma.scripts.Scriptable;
import com.opengamma.util.db.tool.DbTool;

/**
 * Tool class that creates and initializes the example database.
 */
@Scriptable
public class ExampleDatabaseCreator {

  /** Logger. */
  private static final Logger s_logger = LoggerFactory.getLogger(ExampleDatabaseCreator.class);

  /** Schema. */
  private static final String CONFIG_FILE = "toolcontext/toolcontext-examplesbloomberg.properties";
  /** Shared database URL. */
  private static final String KEY_SHARED_URL = "db.standard.url";
  /** Shared database user name. */
  private static final String KEY_SHARED_USER_NAME = "db.standard.username";
  /** Shared database password. */
  private static final String KEY_SHARED_PASSWORD = "db.standard.password";
  /** Temporary user database URL. */
  private static final String KEY_USERFINANCIAL_URL = "db.userfinancial.url";
  /** Temporary user database user name. */
  private static final String KEY_USERFINANCIAL_USER_NAME = "db.userfinancial.username";
  /** Temporary user database password. */
  private static final String KEY_USERFINANCIAL_PASSWORD = "db.userfinancial.password";
  /** Catalog. */
  private static final String CATALOG = "og-financial";

  //-------------------------------------------------------------------------
  /**
   * Main method to run the tool. No arguments are needed.
   *
   * @param args the arguments, unused
   */
  public static void main(final String[] args) { // CSIGNORE
    try {
      new ExampleDatabaseCreator().run(CONFIG_FILE);
      System.exit(0);
    } catch (final Exception ex) {
      s_logger.error("Caught exception", ex);
      ex.printStackTrace();
      System.exit(1);
    }
  }

  //-------------------------------------------------------------------------
  private void run(String configFile) throws Exception {
    ClassPathResource res = new ClassPathResource(configFile, ClassUtils.getDefaultClassLoader());
    Properties props = new Properties();
    try (InputStream in = res.getInputStream()) {
      if (in == null) {
        throw new FileNotFoundException(configFile);
      }
      props.load(in);
    }
//    -jdbcUrl jdbc:hsqldb:file:data/masterdb/hsqldb/examplesbloomberg-db -database og-financial -user
//    &quot;OpenGamma&quot; -password &quot;OpenGamma&quot; -drop true -create true -createtables true
    // create main database
    s_logger.warn("Creating main database...");
    DbTool dbTool = new DbTool();
    dbTool.setJdbcUrl(Objects.requireNonNull(props.getProperty(KEY_SHARED_URL)));
    dbTool.setUser(props.getProperty(KEY_SHARED_USER_NAME, ""));
    dbTool.setPassword(props.getProperty(KEY_SHARED_PASSWORD, ""));
    dbTool.setCatalog(CATALOG);  // ignored, as it is parsed from the url
    dbTool.setCreate(true);
    dbTool.setDrop(true);
    dbTool.setCreateTables(true);
    dbTool.execute();
    
    // create user database
    s_logger.warn("Creating user database...");
    DbTool dbToolUser = new DbTool();
    dbToolUser.setJdbcUrl(Objects.requireNonNull(props.getProperty(KEY_USERFINANCIAL_URL)));
    dbToolUser.setUser(props.getProperty(KEY_USERFINANCIAL_USER_NAME, ""));
    dbToolUser.setPassword(props.getProperty(KEY_USERFINANCIAL_PASSWORD, ""));
    dbToolUser.setCatalog(CATALOG);  // ignored, as it is parsed from the url
    dbToolUser.setCreate(true);
    dbToolUser.setDrop(true);
    dbToolUser.setCreateTables(true);
    dbToolUser.execute();
    
    // populate the database
    s_logger.warn("Populating main database...");
    new ExampleDatabasePopulator().run("classpath:" + configFile, IntegrationToolContext.class);
    
    s_logger.warn("Successfully created example databases");
  }

}