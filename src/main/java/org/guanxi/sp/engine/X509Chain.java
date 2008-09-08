//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:

package org.guanxi.sp.engine;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.guanxi.common.metadata.IdPMetadata;
import org.guanxi.common.metadata.IdPMetadataManager;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.xal.w3.xmldsig.X509DataType;

public class X509Chain {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(X509Chain.class.getName());

  /** This is our cert store, built from the files in pathToCertsStore */
  private static X509Certificate[] x509CertsInStore = null;
  /** We'll use this to generate X509s on the fly from metadata */
  private static CertificateFactory certFactory = null;

  /**
   * Default constructor
   *
   * @param certsStore Full path of where our certificates are stored in SAML2 metadata format
   */
  public X509Chain() {
    try {
      // Get the factory ready for X509s
      certFactory = CertificateFactory.getInstance("x.509");
      // Load up our cert store
      loadX509CertsFromMetadataManager();
    }
    catch(CertificateException ce) {
      logger.error(ce);
    }
  }

  /**
   * Processes all the X509 certificates contained in a KeyInfo element. We're looking for
   * a certificate we have in the cert store and also that it's one we trust.
   *
   * @param keyInfo KeyInfo object containing one or more X509 certificates
   * @return true if we trust the issuer of the matched certificate otherwise if we don't
   * or we can't find the certificate in our cert store
   */
  public boolean verifyChain(KeyInfoType keyInfo) {
    boolean verified = false;

    // Get all the X509Data elements from the KeyInfo element
    X509DataType[] x509Data = keyInfo.getX509DataArray();

    // Cycle through all the <ds:X509Data> elements
    for (int c=0; c < x509Data.length; c++) {
      // Get all the raw <ds:X509Certificate> bytes from the current <ds:X509Data>...
      byte[][] x509CertBytes = x509Data[c].getX509CertificateArray();

      // ...and convert them to X509Certificate objects
      X509Certificate[] x509CertsFromXML = loadCertsFromXML(x509CertBytes);

      // Compare the X509Certificate objects with those in the store to find the signer's cert
      X509Certificate x509Signer = findSignerCert(x509CertsFromXML);

      // If we didn't recognise any certs continue with any more <ds:X509Data> elements
      if (x509Signer == null) {
        continue;
      }

      /* If there's only one certificate, then by now we've recognised it so indicate
       * that the chain (of one) has been verified.
       */
      if (x509CertBytes.length == 1) {
        verified = true;
        break;
      }

      /* We've found the signer's certificate, so now find the next cert in the chain.
       * The signer's certificate's Issuer will be the Subject of the next one in the
       * chain.
       */
      X509Certificate rootCert = findNextCertInChain(x509CertsFromXML, x509Signer.getIssuerDN().getName());
      int certCount = x509CertBytes.length;
      while ((certCount != 0) && (rootCert != null)) {
        rootCert = findNextCertInChain(x509CertsFromXML, rootCert.getSubjectDN().getName());
        certCount--;
      }

      // If there's something wrong with the root cert then we can't verify
      verified = rootCert != null && isRootCertTrusted(rootCert);
    } // for (int c=0; c < x509Data.length; c++)

    return verified;
  }
  
  /**
   * This will load the certificates from the metadata that exists in the manager.
   * This is the only way to load the certificates now - the file based metadata
   * should be loaded into the manager and then use this method to replicate the
   * old loadX509CertsFromMetadata method.
   */
  public static void loadX509CertsFromMetadataManager() {
    Set<Certificate> x509Certs = new HashSet<Certificate>(); 
    // HashSet is used because the Certificate object implements a hashCode which states:
    //  Returns a hashcode value for this certificate from its encoded form.
    // and thus should be suitable for determining if duplicates exist
    
    try {
      // this ditches the existing certificates as the only certificates in the chain
      // should be the ones that come from the loaded metadata
      for ( IdPMetadata current : IdPMetadataManager.getManager().getMetadata() ) {
        byte[] certificate;
        
        certificate = current.getSigningCertificate();
        if ( certificate != null ) {
          x509Certs.add(certFactory.generateCertificate(new ByteArrayInputStream(certificate)));
        }
      }
      
      x509CertsInStore = x509Certs.toArray(new X509Certificate[x509Certs.size()]);
    }
    catch ( Exception e ) {
      logger.error("Unable to load certificates from loaded metadata.", e);
    }
  }
  
  /**
   * This will update the given truststore to include the provided certificate under the given alias.
   * If an entry already exists at the given alias then it will be deleted and this new entry will
   * be added. This will write to a temporary file before deleting the original truststore to help prevent
   * errors, but this will overwrite any file that is named <truststoreFile>.temp.
   * 
   * This must not be called on keystores - only on truststores.
   * 
   * @param truststoreFile            This is the location of the truststore to update
   * @param truststorePassword        This is the password for the truststore
   * @param certificate               This is the certificate to store in the truststore. This should be the server certificate of the IdP AA URL.
   * @param alias                     This is the alias to store the certificate under. This should be the entityID of the IdP which uses the certificate.
   * @throws KeyStoreException        If there is a problem instantiating the truststore, deleting the original alias from the truststore, or adding the new certificate.
   * @throws IOException              If there is a problem reading or writing the truststore.
   * @throws CertificateException     If there is a problem loading or saving the truststore.
   * @throws NoSuchAlgorithmException If there is a problem loading or saving the truststore.
   */
  public static void updateTrustStore(File truststoreFile, String truststorePassword, X509Certificate certificate, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    InputStream  in;
    OutputStream out;
    KeyStore     truststore;
    File         temporaryFile;
    
    // load the truststore
    truststore = KeyStore.getInstance("jks");
    in         = new FileInputStream(truststoreFile);
    try {
      truststore.load(in, truststorePassword.toCharArray());
    }
    finally {
      in.close();
    }
    
    // update the truststore
    if ( truststore.containsAlias(alias) ) {
      truststore.deleteEntry(alias);
    }
    truststore.setCertificateEntry(alias, certificate);
    
    // save the truststore to the temporary file
    temporaryFile = new File(truststoreFile.getAbsolutePath() + ".temp");
    out           = new FileOutputStream(temporaryFile);
    try {
      truststore.store(out, truststorePassword.toCharArray());
    }
    finally {
      out.close();
    }
    
    // replace the original file with the newly created truststore
    truststoreFile.delete();
    temporaryFile.renameTo(truststoreFile);
  }
  
  /**
   * This will update the truststore to set the certificate associated with the alias provided.
   * 
   * @param truststore
   * @param certificate
   * @param alias
   * @throws KeyStoreException
   */
  public static void updateTrustStore(KeyStore truststore, X509Certificate certificate, String alias) throws KeyStoreException {
    if ( truststore.containsAlias(alias) ) {
      truststore.deleteEntry(alias);
    }
    truststore.setCertificateEntry(alias, certificate);
  }
  
  /**
   * This will update the truststore to contain all Attribute Authority URL Certificates that are
   * present in the metadata manager entries.
   * 
   * @param truststore
   * @throws CertificateException 
   * @throws KeyStoreException 
   */
  public static void updateTrustStoreFromMetadataManager(KeyStore truststore) throws KeyStoreException, CertificateException {
    byte[] certificate;
    
    for ( IdPMetadata current : IdPMetadataManager.getManager().getMetadata() ) {
      certificate = current.getAACertificate();
      if ( certificate != null ) {
        updateTrustStore(truststore, 
                         (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificate)), 
                         current.getEntityID());
      }
    }
  }

  /**
   * Converts an array of raw X509 certificates to an array of X509Certificate
   *
   * @param x509CertBytes array of raw X509 certificates
   * @return array of X509Certificate
   */
  private X509Certificate[] loadCertsFromXML(byte[][] x509CertBytes) {
    Vector<Certificate> x509Certs = new Vector<Certificate>();

    try {
      for (int c=0; c < x509CertBytes.length; c++) {
        ByteArrayInputStream certByteStream = new ByteArrayInputStream(x509CertBytes[c]);
        X509Certificate x509Cert = (X509Certificate)certFactory.generateCertificate(certByteStream);
        certByteStream.close();
        x509Certs.add(x509Cert);
      }
    }
    catch(CertificateException ce) {
      logger.error(ce);
    }
    catch(IOException ioe) {
      logger.error(ioe);
    }

    X509Certificate[] x509Certificates = null;
    if (x509Certs != null) {
      x509Certificates = new X509Certificate[x509Certs.size()];
      x509Certs.copyInto(x509Certificates);
    }

    return x509Certificates;
  }

  /**
   * Compares the Subject DN of a set of X509 certificates with the Subject DN of the
   * X509 certificates in the cert store to get a match. It takes the last certificate
   * matched as the one it's looking for.
   * What we're doing is being given a load of X509s from, perhaps, a SAML Response
   * and trying to match one of them with an X509 that's in our store.
   *
   * @param x509Certs array of X509Certificate objects
   * @return X509Certificate representing the cert in the store that is a match for
   * one in x509Certs
   */
  private X509Certificate findSignerCert(X509Certificate[] x509Certs) {
    boolean signerCertFound = false;

    int c;
    for (c=0; c < x509Certs.length; c++) {
      for (int cc=0; cc < x509CertsInStore.length; cc++) {
        // Try and match the Subject Names
        if (x509Certs[c].getSubjectDN().equals(x509CertsInStore[cc].getSubjectDN()))
          signerCertFound = true;
      }

      if (signerCertFound)
        break;
    }

    if (signerCertFound)
      return x509Certs[c];
    else
      return null;
  }

  /**
   * Given an issuer, tries to find an X509 that has that issuer as it's subject dn
   *
   * @param x509Certs array of X509Certificate to search
   * @param issuerName issuer name to look for as a subject dn
   * @return X509Certificate that matches isser name to subject dn or null if none found
   */
  private X509Certificate findNextCertInChain(X509Certificate[] x509Certs, String issuerName) {
    boolean found = false;

    // Have to match subjectName with Issuer from one of the x509Certs
    int c;
    for (c=0; c < x509Certs.length; c++) {
      if (x509Certs[c].getSubjectDN().getName().equals(issuerName)) {
        found = true;
        break;
      }
    }

    if (found)
      return x509Certs[c];
    else
      return null;
  }

  /**
   * Provides a way to check if we trust the subject of an X509 certificate
   *
   * @param rootCert X509Certificate to check for a trust relationship
   * @return true if we trust the subject of rootCert otherwise false
   */
  private boolean isRootCertTrusted(X509Certificate rootCert) {
    if (rootCert != null)
      return true;
    else
      return false;
  }

  /**
   * Looks for XML files
   */
  static class MetadataFileFilter implements FilenameFilter {
    public boolean accept(File file, String name) {
      return name.endsWith(".xml");
    }
  }
}
