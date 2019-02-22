package com.github.susom.mhealth.server.container;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseException;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.database.OptionsOverride;
import com.github.susom.mhealth.server.apis.MyHeartCountsApi;
import com.github.susom.mhealth.server.apis.PortalServerApi;
import com.github.susom.mhealth.server.apis.ResearcherApi;
import com.github.susom.mhealth.server.apis.SageApi;
import com.github.susom.mhealth.server.apis.SageReal;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeApi;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeReal;
import com.github.susom.mhealth.server.apis.TwentyThreeAndMeStubApi;
import com.github.susom.mhealth.server.services.Mailer;
import com.github.susom.vertx.base.Security;
import com.github.susom.vertx.base.SecurityImpl;
import com.github.susom.vertx.base.VertxBase;
import com.github.susom.vertx.base.shaded.org.springframework.core.io.ClassPathResource;
import com.github.susom.vertx.base.shaded.org.springframework.core.io.FileSystemResource;
import com.github.susom.vertx.base.shaded.org.springframework.core.io.Resource;
import com.github.susom.vertx.base.shaded.org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilePermission;
import java.io.PrintStream;
import java.lang.reflect.ReflectPermission;
import java.net.MalformedURLException;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.SecureRandom;
import java.security.SecurityPermission;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.PropertyPermission;
import java.util.Scanner;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.apache.commons.lang3.concurrent.ConcurrentException;
import org.apache.commons.lang3.concurrent.LazyInitializer;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.rootRouter;

/**
 * API server to respond to the MyHeart Counts iOS application.
 */
public class Main {
  private static final Logger log = LoggerFactory.getLogger(Main.class);
  private static final Object lock = new Object();
  private Instant statusTime = Instant.now();
  private int statusCode = 200;
  private String statusMessage = "{\n  \"status\": \"WARNING\",\n  \"message\": "
      + "\"Waiting for status check to start\",\n  \"lastRefresh\": \""
      + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";

  public static void main(String[] args) {
    new Main().run(args);
  }

  public void run(String[] args) {
    try {
      // Vertx logs to JUL unless we tell it otherwise
      System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

      // Running in IDE may put you at the top level directory, where Vertx can't find things
      if (new File("mhealth-server/pom.xml").exists()) {
        System.setProperty("vertx.cwd", "mhealth-server");
      }

      // Useful, but also serves to dump any logging related errors before we redirect sout and serr
      if (System.getProperty("log4j.configuration") != null) {
        log.info("Configuring log4j using: " + System.getProperty("log4j.configuration"));
      } else {
        log.info("Configuring log4j from the classpath");
      }

      // Redirect console into slf4j log
      System.setOut(createLoggingProxy(System.out));
      System.setErr(createLoggingProxy(System.err));

//      System.setProperty("java.security.policy", "=java.policy");
//      System.setSecurityManager(new SecurityManager());
      startSecurityManager();

      Vertx vertx = Vertx.vertx();

      String propertiesFile = System.getProperty("local.properties", "local.properties");
      Config config = Config.from().systemProperties().propertyFile(propertiesFile.split(":")).get();
      Builder db = DatabaseProviderVertx.pooledBuilder(vertx, config).withOptions(new OptionsOverride() {
        @Override
        public Calendar calendarForTimestamps() {
          return Calendar.getInstance(TimeZone.getTimeZone("America/Los_Angeles"));
        }
      }).withSqlParameterLogging();
      SecureRandom random = VertxBase.createSecureRandom(vertx);

      // Avoid using sessions by cryptographically signing tokens with JWT
      // To create the private key do something like this:
      // keytool -genseckey -keystore keystore.jceks -storetype jceks -storepass secret \
      //         -keyalg HMacSHA256 -keysize 2048 -alias HS256 -keypass secret
      // For more info: https://vertx.io/docs/vertx-auth-jwt/js/
      KeyStoreOptions keyStore = new KeyStoreOptions();
      keyStore.setType(config.getString("jwt.keystore.type", "jceks"));
      keyStore.setPath(config.getString("jwt.keystore.path", "keystore.jceks"));
      keyStore.setPassword(config.getString("jwt.keystore.password", "secret"));
      Lazy<JWTAuth> jwt = Lazy.initializer(() -> JWTAuth.create(vertx,new JWTAuthOptions().setKeyStore(keyStore)));

      Set<String> argSet = new HashSet<>(Arrays.asList(args));

      if (argSet.contains("mhealth") || argSet.isEmpty()) {
        Router root = Router.router(vertx);
        String context = "/" + config.getString("mhc.web.context", "mhc");
        TwentyThreeAndMeReal twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);
        TwentyThreeAndMeApi twentyThree = new TwentyThreeAndMeApi(db, random, config, twentyThreeAndMe);
        MyHeartCountsApi mhcApi = new MyHeartCountsApi(db, random, jwt.get(), config, vertx, twentyThree);
        mhcApi.loadInvalidTokenCache(r -> {
          if (r.succeeded()) {
            log.info(r.result());
          } else {
            log.error("Error loading invalid token cache", r.cause());
          }
        });
        root.mountSubRouter(context, mhcApi.router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8080, result ->
            log.info("Started " + context + " on port " + 8080)
        );
        // We want only one instance of the batch running, so disable by default
        Integer intervalSeconds = config.getInteger("23andme.batch.interval.seconds", 0);
        if (intervalSeconds > 0) {
          start23andMeBatchDownload(vertx, mhcApi.twentyThreeAndMe, intervalSeconds);
          log.info("Batch downloader for 23andMe will run every " + intervalSeconds + " seconds");
        } else {
          log.info("Batch downloader for 23andMe is disabled (set 23andme.batch.interval.seconds to enable)");
        }
        Integer intervalSecnds = config.getInteger("invalid.token.batch.interval.seconds", 0);
        if (intervalSecnds > 0) {
          loadInvalidTokenCache(vertx, mhcApi, intervalSecnds);
          log.info("Batch process for loading invalid tokens run every " + intervalSecnds + " seconds");
        } else {
          log.info("Batch process for loading invalid tokens is disabled(set invalid.token.batch.interval.seconds to enable)");
        }
      }

      if (argSet.contains("23andme-stub") || argSet.isEmpty()) {
        Router root = Router.router(vertx);
        String context = "/" + config.getString("23andme-stub.web.context", "23andme-stub");
        root.mountSubRouter(context, new TwentyThreeAndMeStubApi(random, config).router(vertx));
        root.get("/status").handler(rc -> rc.response().setStatusCode(200).end(
            "{\n  \"status\": \"OK\",\n  \"message\": \"OVERALL STATUS: OK\",\n  \"lastRefresh\": \""
                + DateTimeFormatter.ISO_INSTANT.format(Instant.now()) + "\"\n}\n"));
        root.get("/status/app").handler(rc -> rc.response().setStatusCode(200).end(
            "{\n  \"status\": \"OK\",\n  \"message\": \"OVERALL STATUS: OK\",\n  \"lastRefresh\": \""
                + DateTimeFormatter.ISO_INSTANT.format(Instant.now()) + "\"\n}\n"));
        vertx.createHttpServer().requestHandler(root::accept).listen(8000, result ->
            log.info("Started " + context + " on port " + 8000)
        );
      }

      if (argSet.contains("23andme") || argSet.isEmpty()) {
        TwentyThreeAndMeReal twentyThreeAndMe = new TwentyThreeAndMeReal(vertx, config);
        TwentyThreeAndMeApi twentyThree = new TwentyThreeAndMeApi(db, random, config, twentyThreeAndMe);
        Router root = Router.router(vertx);
        String context = "/" + config.getString("23andme.web.context", "23andme");
        root.mountSubRouter(context, twentyThree.router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8001, result ->
            log.info("Started " + context + " on port " + 8001)
        );
        // We want only one instance of the batch running, so disable by default
        Integer intervalSeconds = config.getInteger("23andme.batch.interval.seconds", 0);
        if (intervalSeconds > 0) {
          start23andMeBatchDownload(vertx, twentyThree, intervalSeconds);
          log.info("Batch downloader for 23andMe will run every " + intervalSeconds + " seconds");
        } else {
          log.info("Batch downloader for 23andMe is disabled (set 23andme.batch.interval.seconds to enable)");
        }
      }

      if (argSet.contains("mypart") || argSet.isEmpty()) {
        Mailer mailer = createMailer(config);
        Router root = Router.router(vertx);
        String apiContext = "/" + config.getString("portal.api.context", "server");
        SageApi sageApi = new SageReal(vertx, config);
        PortalServerApi portalApi = new PortalServerApi(db, random, mailer, config, sageApi);
                root.mountSubRouter(apiContext, portalApi.router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8002, result ->
            log.info("Started " + apiContext + " on port 8002")
        );
        root = Router.router(vertx);
        String webContext = "/" + config.getString("portal.web.context", "participant");
        root.mountSubRouter(webContext, new ParticipantPortal(db, random, mailer, config).router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8003, result ->
            log.info("Started " + webContext + " on port 8003")
        );
      }

      if (argSet.contains("mhealthdata") || argSet.isEmpty()) {
        Router root = Router.router(vertx);
        String webContext = "/" + config.getString("researcher.api.context", "researcherApi");
        ResearcherApi researcherApi = new ResearcherApi(db, random,  config);
        root.mountSubRouter(webContext, researcherApi.router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8006, result ->
            log.info("Started " + webContext + " on port 8006")
        );
        // We want only one instance of the batch running, so disable by default
        Integer intervalSeconds = config.getInteger("upload.sequence.batch.interval.seconds", 0);
        if (intervalSeconds > 0) {
          startUploadSequenceBatchProcess(vertx, researcherApi, intervalSeconds);
          log.info("Batch process for upload sequence will run every " + intervalSeconds + " seconds");
        } else {
          log.info("Batch process for upload sequence is disabled(set upload.sequence.batch.interval.seconds to enable)");
        }
      }

      if (argSet.contains("mhealthadmin") || argSet.isEmpty()) {
        String context = '/' + config.getString("researcher.api.context", "researcher");
        final HashMap<String, @Untainted String> fileToSql = new HashMap<>();
        Router root = rootRouter(vertx, context);
        Security security = new SecurityImpl(vertx, root, random, config::getString);
        String path = config.getString("admin.sql.directory","static/adminSql");
        loadSqlFromFiles(path,"**/*" , "", fileToSql,(VertxInternal)vertx);
        Router router = security.authenticatedRouter(context);
        new ResearcherPortal(db, random,  config, security, fileToSql).addToRouter(vertx, router);
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8007, result -> {
              if (result.succeeded()) {
                int actualPort = result.result().actualPort();
                log.info("Started server: http://localhost:{}{}/", actualPort, context);
              } else {
                log.error("Could not start server on port 8007", result.cause());
              }
            }
        );
      }

      // Just a sample I am using right now for testing authentication
      if (argSet.contains("mystudy") || argSet.isEmpty()) {
        Router root = Router.router(vertx);
        String apiContext = "/" + config.getString("mystudy.api.context", "mystudy");
        root.mountSubRouter(apiContext, new MyStudy(db, random, jwt.get(), config).router(vertx));
        addStatusHandlers(root);
        vertx.createHttpServer().requestHandler(root::accept).listen(8004, result ->
            log.info("Started " + apiContext + " on port 8004 (http://localhost:8004/mystudy/?q=1#m=yay)")
        );
      }

      Integer intervalSeconds = config.getInteger("healthcheck.interval.seconds", 60);
      if (intervalSeconds > 0
          && (!argSet.contains("23andme-stub") || (argSet.contains("23andme-stub") && argSet.size() > 1))) {
        startStatusChecker(vertx, db, intervalSeconds);
      }

      // Attempt to do a clean shutdown on JVM exit
      Runtime.getRuntime().addShutdownHook(new Thread(() -> {
        log.info("Trying to stop the server nicely");
        try {
          synchronized (lock) {
            // First shutdown Vert.x
            vertx.close(h -> {
              log.info("Vert.x stopped, now closing the connection pool");
              synchronized (lock) {
                // Then shutdown the database pool
                db.close();
                log.info("Server stopped");
                lock.notify();
              }
            });
            lock.wait(30000);
          }
        } catch (Exception e) {
          e.printStackTrace();
        }
      }));

      // Make sure we cleanly shutdown Vert.x and the database pool on exit
//      addShutdownHook(vertx, db::close);
    } catch (Exception e) {
      log.error("Unexpected exception in main()", e);
      System.exit(1);
    }
  }

  private void start23andMeBatchDownload(Vertx vertx, TwentyThreeAndMeApi twentyThree, int intervalSeconds) {
    vertx.setPeriodic(intervalSeconds * 1000, (id) -> {
      MDC.clear();
      MDC.put("userId", "<polling>");
      twentyThree.twentyThreeAndMeDownloadHandler(r -> {
        if (r.succeeded()) {
          log.info(r.result());
        } else {
          log.error("Error running 23andMe batch download", r.cause());
        }
//        MDC.clear();
      });
    });
  }

  private void startUploadSequenceBatchProcess(Vertx vertx, ResearcherApi researcherApi, int intervalSeconds) {
    vertx.setPeriodic(intervalSeconds * 1000, (id) -> {
      MDC.clear();
      MDC.put("userId", "<polling>");
      researcherApi.uploadSequenceHandler(r -> {
        if (r.succeeded()) {
          log.info(r.result());
        } else {
          log.error("Error running uploadSequence batch process", r.cause());
        }
//        MDC.clear();
      });
    });
  }

  private void loadInvalidTokenCache(Vertx vertx, MyHeartCountsApi mhcApi, int intervalSeconds) {
    vertx.setPeriodic(intervalSeconds * 1000, (id) -> {
      MDC.clear();
      MDC.put("userId", "<polling>");
      mhcApi.loadInvalidTokenCache(r -> {
        if (r.succeeded()) {
          log.info(r.result());
        } else {
          log.error("Error running load invalid token cache process", r.cause());
        }
//        MDC.clear();
      });
    });
  }

  private void startStatusChecker(Vertx vertx, Builder db, int intervalSeconds) {
    // DCS status per https://medwiki.stanford.edu/display/apps/Status+Page+Policy+and+Standards
    Handler<Long> statusCheck = h -> {
      MDC.clear();
      MDC.put("userId", "<health-check>");
      db.transactAsync(dbs -> {
        return dbs.get().toSelect("select ?" + dbs.get().flavor().fromAny())
            .argDateNowPerDb().queryFirstOrNull(r -> {
              Date appDate = dbs.get().nowPerApp();
              Date dbDate = r.getDateOrNull();

              if (dbDate == null) {
                throw new DatabaseException("Expecting a date in the result");
              }

              if (Math.abs(appDate.getTime() - dbDate.getTime()) > 3600000) {
                throw new DatabaseException("App and db time are over an hour apart (check your timezones) app: "
                    + DateTimeFormatter.ISO_INSTANT.format(appDate.toInstant()) + " db: "
                    + DateTimeFormatter.ISO_INSTANT.format(dbDate.toInstant()));
              }

              if (Math.abs(appDate.getTime() - dbDate.getTime()) > 30000) {
                throw new DatabaseException("App and db time are over thirty seconds apart (check your clocks) app: "
                    + DateTimeFormatter.ISO_INSTANT.format(appDate.toInstant()) + " db: "
                    + DateTimeFormatter.ISO_INSTANT.format(dbDate.toInstant()));
              }

              return null;
            });
      }, result -> {
        statusTime = Instant.now();
        if (result.succeeded()) {
          statusCode = 200;
          statusMessage = "{\n  \"status\": \"OK\",\n  \"message\": \"OVERALL STATUS: OK\",\n  \"lastRefresh\": \""
              + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";
        } else {
          statusCode = 500;
          statusMessage = "{\n  \"status\": \"ERROR\",\n  \"message\": \"Cannot connect to database\",\n  "
              + "\"lastRefresh\": \"" + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";
          log.error("Problem with the database health check", result.cause());
        }
      });
      MDC.clear();
    };
    statusCheck.handle(vertx.setPeriodic(intervalSeconds * 1000, statusCheck));
  }

  private void addStatusHandlers(Router root) {
    // DCS status per https://medwiki.stanford.edu/display/apps/Status+Page+Policy+and+Standards
    Handler<RoutingContext> handler = rc -> {
      if (statusTime.isBefore(Instant.now().minus(5, ChronoUnit.MINUTES))) {
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .setStatusCode(500).end("{\n  \"status\": \"ERROR\",\n  \"message\": \"Status check is "
            + "hung\",\n  \"lastRefresh\": \"" + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n");
      } else {
        rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .setStatusCode(statusCode).end(statusMessage);
      }
    };
    root.get("/status").handler(handler);
    root.get("/status/app").handler(handler);
  }

  public static PrintStream createLoggingProxy(PrintStream realPrintStream) {
    return new PrintStream(realPrintStream) {
      public void print(final String string) {
        log.warn(string, new Exception("Do not write to the console"));
      }

      public void println(final String string) {
        log.warn(string, new Exception("Do not write to the console"));
      }
    };
  }

  private static void startSecurityManager() throws MalformedURLException {
    String tempDir = System.getProperty("java.io.tmpdir");
    String workDir = System.getProperty("user.dir");
//    String homeDir = System.getProperty("user.home");
    String javaDir = System.getProperty("java.home");

    log.debug(
        "Directories for initializing the SecurityManager:\n  temp: " + tempDir + "\n  work: " + workDir + "\n  java: "
            + javaDir);

    // Figure out whether we are running exploded (IDE) or from a fat jar
    // We need different policies because files/resources are accessed differently
//    String main = ClassLoader.getSystemResource("com/github/susom/mhealth/server/container/Main.class").toString();
//    boolean runningFromClasses = main.startsWith("file:");

    // Walk the classpath to figure out all the relevant codebase locations for our policy
    String javaHome = javaDir;
    if (javaHome.endsWith("/jre")) {
      javaHome = javaHome.substring(0, javaHome.length() - 5);
    }
    Set<String> jdkLocations = new HashSet<>();
    Set<String> appLocations = new HashSet<>();
    String[] classpath = System.getProperty("java.class.path").split(":");
    for (String entry : classpath) {
      if (entry.startsWith(javaHome)) {
        jdkLocations.add(entry);
      } else {
        appLocations.add(entry);
      }
//      System.out.println("entry: "  + entry);
    }

    Permissions appPerms = new Permissions();

    appPerms.add(new FilePermission(workDir + "/webroot", "read")); // dev only
    appPerms.add(new FilePermission(workDir + "/mhealth-server/target/classes/-", "read")); // dev only
//    perms.add(new FilePermission(workDir + "/mhealth-server/target/classes/webroot/portal", "read")); // dev only
//    perms.add(new FilePermission(workDir + "/mhealth-server/target/classes/webroot/portal", "read")); // dev only
//    perms.add(new FilePermission(workDir + "/mhealth-server/target/classes/webroot/portal/index.nocache.html", "read")); // dev only
    appPerms.add(new FilePermission(workDir + "/mhealth-server/src/main/resources/-", "read")); // dev only
    appPerms.add(new FilePermission(workDir + "/emailFile", "write")); // dev only

    // Files and directories the app will access
    appPerms.add(new FilePermission(workDir + "/local.properties", "read"));
    appPerms.add(new FilePermission(workDir + "/.vertx/-", "read,write"));
    appPerms.add(new FilePermission(workDir + "/conf/-", "read"));
    appPerms.add(new FilePermission(workDir + "/logs/-", "read,write"));
    appPerms.add(new FilePermission(tempDir, "read,write"));
    appPerms.add(new FilePermission("/System/Library/Java/Extensions/-", "read"));
    appPerms.add(new FilePermission("/Library/Java/JavaVirtualMachines/jdk1.8.0_60.jdk/Contents/Home/jre/lib/-", "read"));

    // Ports we will serve on
    appPerms.add(new SocketPermission("localhost:1024-", "accept"));
    appPerms.add(new SocketPermission("smtp.stanford.edu:587", "connect"));

    // Everything tries to read some system property
    appPerms.add(new PropertyPermission("*", "read"));

    // These seem like bugs in vertx/netty (should not fail if these permissions are not granted)
    appPerms.add(new RuntimePermission("setIO"));
    appPerms.add(new PropertyPermission("io.netty.noJdkZlibDecoder", "write"));
    appPerms.add(new PropertyPermission("sun.nio.ch.bugLevel", "write"));

    // Emailer does DNS lookup on localhost hostname
    appPerms.add(new SocketPermission("*", "resolve"));

    // Not sure about these
    appPerms.add(new ReflectPermission("suppressAccessChecks"));
    appPerms.add(new RuntimePermission("accessDeclaredMembers"));
    appPerms.add(new RuntimePermission("getClassLoader"));
    appPerms.add(new RuntimePermission("setContextClassLoader"));
    appPerms.add(new RuntimePermission("loadLibrary.sunec"));
    appPerms.add(new RuntimePermission("accessClassInPackage.sun.*"));
    appPerms.add(new SecurityPermission("putProviderProperty.SunJCE"));
    appPerms.add(new SecurityPermission("putProviderProperty.SunEC"));
    appPerms.add(new NetPermission("getNetworkInformation"));
    appPerms.add(new FilePermission("/proc/sys/net/core/somaxconn", "read"));

    // Connect to the database
    appPerms.add(new SocketPermission("localhost:5432", "connect,resolve"));

//    CodeSource javaExtensions = new CodeSource(new URL("file:" + javaDir), new Certificate[0]);
    Permissions jdkPerms = new Permissions();
    jdkPerms.add(new AllPermission());

    Permissions noPerms = new Permissions();
    noPerms.add(new AllPermission());

    Policy.setPolicy(new Policy() {
      @Override
      public PermissionCollection getPermissions(CodeSource codesource) {
        if (jdkLocations.contains(codesource.getLocation().getPath())) {
//          System.err.println("Returning all permissions for codesource: " + codesource.getLocation());
          return jdkPerms;
        } else if (appLocations.contains(codesource.getLocation().getPath())) {
//          System.err.println("Returning application permissions for codesource: " + codesource.getLocation());
          return jdkPerms;
        }
//        System.err.println("Returning no permissions for codesource: " + codesource.getLocation());
        return noPerms;
      }
    });

    System.setSecurityManager(new SecurityManager() {
      final Set<Permission> alreadyDenied = new HashSet<>();

      public void checkPermission(Permission perm, Object context) {
        try {
          super.checkPermission(perm, context);
        } catch (SecurityException e) {
          synchronized (alreadyDenied) {
            if (!alreadyDenied.contains(perm)) {
              log.warn("Denying permission: " + perm + " context: " + context, e);
              alreadyDenied.add(perm);
            }
          }
          throw e;
        }
      }

      public void checkPermission(Permission perm) {
        try {
          super.checkPermission(perm);
        } catch (SecurityException e) {
          synchronized (alreadyDenied) {
            if (!alreadyDenied.contains(perm)) {
              log.warn("Denying permission: " + perm, e);
              alreadyDenied.add(perm);
            }
          }
          throw e;
        }
      }
    });
  }

  private static Mailer createMailer(Config config) {
    MailerFactory mailerF = new MailerFactory();
    return mailerF.create(config);
  }

  /**
   * Add a directory from the classpath, including all contained files and
   * directories recursively.
   *
   * @param dir a directory relative to the classpath root, (e.g. "static/mystuff")
   *            where resources will be loaded from
   * @param prefix a prefix that will be added to the resources within dir (e.g. "mystuff");
   *               may be the empty string if you don't want an additional prefix
   */
  @SuppressWarnings("tainting")
  private  void loadSqlFromFiles(@Nonnull String dir, @Nonnull String pattern, @Nonnull String prefix, Map<String, @Untainted String> fileTosql, VertxInternal vertx) {
    if (!dir.endsWith("/")) {
      dir = dir + "/";
    }
    if (!prefix.equals("") && !prefix.startsWith("/")) {
      prefix = "/" + prefix;
    }
    if (!prefix.equals("") && !prefix.endsWith("/")) {
      prefix = prefix + "/";
    }

    try {
      ClassLoader cl = Thread.currentThread().getContextClassLoader();
      PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(cl) {
      };
      // We want to use classpath*: because that searches over the entire classpath
      // rather than allowing one directory to mask a later one
      Resource[] resources = resolver.getResources("classpath*:" + dir + pattern);
      if (resources != null) {
        for (Resource resource : resources) {
          if (resource.isReadable()) {
            if (ClassPathResource.class.isAssignableFrom(resource.getClass())) {
              String resourcePath = ((ClassPathResource) resource).getPath();
              if (resourcePath.endsWith("/")) {
                continue;
              }
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf(dir) + dir.length());
              if (fileTosql.containsKey(servePath)) {
                log.trace("Skipping duplicate classpath resource {} ({})", servePath, resourcePath);
                continue;
              }
              /* This copies the file into the .vertx cache directory to be served via sendFile()*/
              File file = vertx.resolveFile(resourcePath);
              @Untainted String sql = getSqlFromFile(file);
              log.trace("Adding classpath resource {} ({})", servePath, resourcePath);
              fileTosql.put(servePath, sql);
            } else if (resource instanceof FileSystemResource) {
              File file = ((FileSystemResource) resource).getFile();
              if (file.isDirectory()) {
                continue;
              }
              String resourcePath = file.getPath();
              // This isn't quite correct because it assumes the absolute path does
              // not contain dir, but I haven't figured out how to know the base yet
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf("/" + dir) + 1).substring(dir.length());
              if (fileTosql.containsKey(servePath)) {
                log.trace("Skipping duplicate file resource {} ({})", servePath, resourcePath);
                continue;
              }
              log.trace("Adding file resource {} ({})", servePath, resourcePath);
              @Untainted String sql = getSqlFromFile(file);
              fileTosql.put(servePath, sql);

            }
          }
        }
      }
    } catch (Exception e) {
            throw new RuntimeException("Could not locate File for resource dir: " + dir, e);
          }
        }

    private String getSqlFromFile(File file ) {
      FileInputStream fis = null;
      String sql = null;
      try {
        fis = new FileInputStream(file);
        Scanner scn = new Scanner(fis);
        sql = scn.useDelimiter(";").next();
        scn.close();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return sql;
    }

  interface Lazy<T> extends Supplier<T> {
    static <L> Lazy<L> initializer(Supplier<L> supplier) {
      return new Lazy<L>() {
        LazyInitializer<L> lazy = new LazyInitializer<L>() {
          @Override
          protected L initialize() throws ConcurrentException {
            return supplier.get();
          }
        };

        @Override
        public L get() {
          try {
            return lazy.get();
          } catch (ConcurrentException e) {
            throw new RuntimeException(e);
          }
        }
      };
    }
  }
}
