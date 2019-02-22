package com.github.susom.mhealth.server.tools;

import com.github.susom.database.DatabaseProvider;
import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.Security;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Just testing how to decrypt a file uploaded from the iOS app.
 * <p/>
 * <p>I generated the public and private keys using openssl:</p>
 * <p/>
 * <pre>
 *   # Generate the private key pair
 *   openssl genrsa -aes128 -out privkey.pem 2048
 *
 *   # Generate the public x509 key to be used for encrypting
 *   openssl req -new -x509 -key privkey.pem -out pubkey.pem
 * </pre>
 * <p/>
 * <p>Copy the public key into the iOS app in /CardioHealth/Resources/Certificates/*.pem
 * so it can be used to encrypt the data.</p>
 */
public class DecryptUploadedFile {
  public static void main(String[] args) {
    DatabaseProvider.fromPropertyFileOrSystemProperties(
        System.getProperty("local.properties", "local.properties")
    ).transact(db -> {
      Security.addProvider(new BouncyCastleProvider());

      // Read the public key
      PemObject publicKey = new PemReader(
          new StringReader(FileUtils.readFileToString(new File("pubkey.pem"), "utf-8"))
      ).readPemObject();
      X509CertificateHolder certHolder = new X509CertificateHolder(publicKey.getContent());
      RecipientId recipientId = new KeyTransRecipientId(certHolder.getIssuer(), certHolder.getSerialNumber());

      // Read the private key
      PEMParser pemParser = new PEMParser(new FileReader("privkey.pem"));
      Object object = pemParser.readObject();
      PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build("garrick".toCharArray());
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      KeyPair privateKeyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
      Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKeyPair.getPrivate());

      // Figure out which files we want to decrypt
      for (Long id : db.get().toSelect("select mh_file_upload_id from mh_file_upload").queryLongs()) {
        byte[] encryptedContent = db.get().toSelect("select content from mh_file_upload_content"
            + " where mh_file_upload_id=?").argLong(id)
            .query(rs -> {
              if (rs.next()) {
                return rs.getBlobBytesOrZeroLen();
              }
              return new byte[0];
            });

        // Decrypt it
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedContent);
        RecipientInformation recInfo = envelopedData.getRecipientInfos().get(recipientId);
        byte[] decrypted = recInfo.getContent(recipient);

        FileUtils.writeByteArrayToFile(new File("decrypted-" + id + ".zip"), decrypted);
      }
    });
  }
}
