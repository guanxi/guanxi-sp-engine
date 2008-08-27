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

import org.guanxi.common.metadata.IdPMetadata_XML_EntityDescriptorType;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.xal.w3.xmldsig.X509DataType;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.apache.log4j.Logger;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.io.*;
import java.util.Vector;

public class X509Chain {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(X509Chain.class.getName());

  /** Full path of where our certificates are stored in SAML2 metadata format */
  private static String pathToCertsStore = null;
  /** This is our cert store, built from the files in pathToCertsStore */
  private static X509Certificate[] x509CertsInStore = null;
  /** We'll use this to generate X509s on the fly from metadata */
  private static CertificateFactory certFactory = null;

  /**
   * Default constructor
   *
   * @param certsStore Full path of where our certificates are stored in SAML2 metadata format
   */
  public X509Chain(String certsStore) {
    try {
      // Store the path to the metadata
      pathToCertsStore = certsStore;
      // Get the factory ready for X509s
      certFactory = CertificateFactory.getInstance("x.509");
      // Load up our cert store
      loadX509CertsFromMetadata();
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
      if (x509Signer == null)
        continue;

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
   * Loads all the IdP metadata files in WEB-INF/config/metadata/idp, extracts their
   * X509 certificates and puts them in a certificate store.
   */
  public static void loadX509CertsFromMetadata() {
    Vector<Certificate> x509Certs = new Vector<Certificate>();

    try {
      // Find all the XML files in the IdP metadata directory
      File idpMetadataDir = new File(pathToCertsStore);
      File[] idpFiles = idpMetadataDir.listFiles(new MetadataFileFilter());

      // Cycle through them all, putting their X509 certificates in the certificate store
      for (int c=0; c < idpFiles.length; c++) {
        EntityDescriptorDocument edDoc = EntityDescriptorDocument.Factory.parse(new File(idpFiles[c].getPath()));
        EntityDescriptorType entityDescriptor = edDoc.getEntityDescriptor();

        /* Looking for:
         * <KeyDescriptor use="signing"> --> assumes only one
         *   <ds:KeyInfo>
         *     <ds:X509Data>
         *       <ds:X509Certificate>
         */
        byte[] bytes = new IdPMetadata_XML_EntityDescriptorType(entityDescriptor).getX509Certificate();

        // Add the X509 certificate to the store. The store
        x509Certs.add(certFactory.generateCertificate(new ByteArrayInputStream(bytes)));
      }
    }
    catch(Exception e) {
      logger.error(e);
    }

    // Dump the harvested X509s into the certificate store
    if (x509Certs != null) {
      x509CertsInStore = new X509Certificate[x509Certs.size()];
      x509Certs.copyInto(x509CertsInStore);
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
