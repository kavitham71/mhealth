package com.github.susom.mhealth.server.test;

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.mhealth.server.apis.UploadRequest;
import com.github.susom.vertx.base.Valid;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.function.Supplier;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.concurrent.ConcurrentException;
import org.apache.commons.lang3.concurrent.LazyInitializer;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
@Parameterized.UseParametersRunnerFactory(VertxUnitRunnerWithParametersFactory.class)
public class UploadPerformanceTestRunner {

  private String fileName;
  private String contentLength;
  private String contentMd5;
  private String sessionToken;
  private Vertx vertx;
  private Lazy<JWTAuth> jwt;
  private Builder realDbb;
  private DatabaseProviderVertx realDbp;


  //parameters pass via this constructor
  public UploadPerformanceTestRunner(String fileName, String contentLength, String contentMd5, String deviceRpid)
      throws Exception {
    this.fileName = fileName;
    this.contentLength = contentLength;
    this.contentMd5 = contentMd5;
    vertx = Vertx.vertx();
    String propertiesFile = System.getProperty("local.properties", "local.properties");
    Config config = Config.from().systemProperties().propertyFile(propertiesFile.split(":")).get();
    Lazy<JWTAuth> jwt = Lazy.initializer(() -> JWTAuth.create(vertx, new JsonObject()
        .put("keyStore", new JsonObject()
            .put("type", "jceks")
            .put("path", config.getString("jwt.keystore.path", "keystore.jceks"))
            .put("password", "secret"))));
    this.sessionToken = jwt.get().generateToken(new JsonObject().put("sub", deviceRpid).put("consented", true),
        new JWTOptions().setExpiresInSeconds(60 * 60 * 24));

  }

  private static String createFile(String name, int length) {
    try {
      File file = new File(name);
      if (!file.exists()) {
        RandomAccessFile f = new RandomAccessFile(file, "rw");
        f.setLength(length);
      }
    } catch (Exception e) {
      System.err.println(e);
    }
    return name;
  }

  //Declares parameters here
  @Parameters
  public static Iterable<Object[]> data1() {
    Object[][] uploadData = new Object[][] {
        { createFile("f1", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "111" },
        { createFile("f2", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "222" },
        { createFile("f3", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "333" },
        { createFile("f4", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "444" },
        { createFile("f5", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "555" },
        { createFile("f6", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "666" },
        { createFile("f7", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "777" },
        { createFile("f8", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "888" },
        { createFile("f9", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "999" },
        { createFile("f10", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "101" },
        { createFile("f1", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "102" },
        { createFile("f2", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "103" },
        { createFile("f3", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "104" },
        { createFile("f4", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "105" },
        { createFile("f5", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "106" },
        { createFile("f6", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "107" },
        { createFile("f7", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "108" },
        { createFile("f8", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "109" },
        { createFile("f9", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "200" },
        { createFile("f10", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "201" },
        { createFile("f1", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "202" },
        { createFile("f2", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "203" },
        { createFile("f3", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "204" },
        { createFile("f4", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "205" },
        { createFile("f5", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "206" },
        { createFile("f6", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "207" },
        { createFile("f7", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "208" },
        { createFile("f8", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "209" },
        { createFile("f9", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "300" },
        { createFile("f10", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "301" },
        { createFile("f1", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "302" },
        { createFile("f2", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "303" },
        { createFile("f3", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "304" },
        { createFile("f4", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "305" },
        { createFile("f5", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "306" },
        { createFile("f6", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "307" },
        { createFile("f7", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "308" },
        { createFile("f8", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "309" },
        { createFile("f9", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "400" },
        { createFile("f10", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "401" },
        { createFile("f1", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "402" },
        { createFile("f2", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "403" },
        { createFile("f3", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "404" },
        { createFile("f4", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "405" },
        { createFile("f5", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "406" },
        { createFile("f6", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "407" },
        { createFile("f7", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "408" },
        { createFile("f8", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "409" },
        { createFile("f9", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "500" },
        { createFile("f10", 1024), "1024", "6RQ57lzGqQV+SXHQFxZCFQ==", "501" },

    };
    return Arrays.asList(uploadData);
  }


  public void testUpload(TestContext context) {

    UploadRequest request = new UploadRequest();
    request.setName(fileName);
    request.setContentLength(Integer.parseInt(contentLength));
    request.setContentMd5(contentMd5);

    Async async = context.async();
    HttpClient client = vertx.createHttpClient();
    client.post(8080, "localhost", "/mhc/api/v1/upload", uploadResponse -> {
      context.assertEquals(201, uploadResponse.statusCode());

      uploadResponse.bodyHandler(body -> {
        String bodyString = body.toString();

        JsonObject response = new JsonObject(bodyString);
        String Id = Valid.nonNull(response.getString("id"),"id cannot be null");
        String Type = Valid.nonNull(response.getString("type"),"type cannot be null");
        context.assertEquals(Type, "UploadSession");
        try {
          client.put(8080, "localhost", "/mhc/api/v1/upload/" + Id, uploadIdResponse -> {
            context.assertEquals(200, uploadIdResponse.statusCode());
            uploadIdResponse.bodyHandler(uploadId -> {
              client.post(8080, "localhost", "/mhc/api/v1/upload/" + Id + "/complete", uploadCompleteResponse -> {
                context.assertEquals(200, uploadCompleteResponse.statusCode());
                uploadCompleteResponse.bodyHandler(uploadComplete -> {
                  client.get(8080, "localhost", "/mhc/api/v1/upload/" + Id + "/status?study=cardiovascular",
                      uploadStatusResponse -> {
                        context.assertEquals(200, uploadStatusResponse.statusCode());
                        uploadStatusResponse.bodyHandler(uploadStatus -> {
                          context.assertTrue(uploadStatus.toString().contains("succeeded"));
                          async.complete();
                        });
                      }).exceptionHandler(context::fail)
                      .putHeader("Bridge-Session", sessionToken).end();

                });
              }).exceptionHandler(context::fail)
                  .putHeader("Bridge-Session", sessionToken)
                  .end();

            });
          }).exceptionHandler(context::fail).putHeader("content-type", "application/zip")
              .putHeader("Bridge-Session", sessionToken)
              .putHeader("User-Agent", "CardioHealth/9 CFNetwork/711.4.6 Darwin/14.5.0®")
              .end(Json.encode(FileUtils.readFileToString(new File(fileName))));
        } catch (Exception e) {
          System.out.println("Exception" + e.getMessage());
        }
      });
    }).exceptionHandler(context::fail).putHeader("content-type", "application/json")
        .putHeader("Bridge-Session", sessionToken)
        .end(Json.encode(request));


  }

  public void deleteFiles() {
    try {
      String[] files = { "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10" };
      for (String fileName : files) {
        File file = new File(fileName);

        if (file.delete()) {
          System.out.println(file.getName() + " is deleted!");
        } else {
          System.out.println("Delete operation  failed.");
        }
      }
    } catch (Exception e) {

      e.printStackTrace();

    }

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
