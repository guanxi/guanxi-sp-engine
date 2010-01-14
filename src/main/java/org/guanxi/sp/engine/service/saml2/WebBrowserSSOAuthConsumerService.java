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

package org.guanxi.sp.engine.service.saml2;

import org.springframework.web.servlet.mvc.multiaction.MultiActionController;
import org.springframework.web.context.ServletContextAware;
import org.springframework.context.MessageSource;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlOptions;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Utils;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.trust.TrustUtils;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.common.definitions.SAML;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.protocol.ResponseDocument;
import org.guanxi.xal.w3.xmlenc.EncryptedKeyDocument;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.sp.Util;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

/**
 * Handles the trust and attribute decryption for SAML2 Web Browser SSO profile.
 *
 * @author alistair
 */
public class WebBrowserSSOAuthConsumerService extends MultiActionController implements ServletContextAware {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(WebBrowserSSOAuthConsumerService.class.getName());
  /** The localised messages to use */
  private MessageSource messages = null;
  /** The view to redirect to if no error occur */
  private String podderView = null;
  /** The view to use to display any errors */
  private String errorView = null;
  /** The variable to use in the error view to display the error */
  private String errorViewDisplayVar = null;

  public void init() {}

  public void destroy() {}

  /**
   * This is the handler for the initial /s2/wbsso/acs page. This receives the
   * browser after it has visited the IdP.
   *
   * @param request ServletRequest
   * @param response ServletResponse
   * @throws java.io.IOException
   * @throws org.guanxi.common.GuanxiException
   * @throws java.security.KeyStoreException
   * @throws java.security.NoSuchAlgorithmException
   * @throws java.security.cert.CertificateException
   */
  public void acs(HttpServletRequest request, HttpServletResponse response) throws IOException, GuanxiException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    String guardSession = request.getParameter("RelayState");
    String b64SAMLResponse = request.getParameter("SAMLResponse");

    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardSession.replaceAll("GUARD", "ENGINE"));

    try {
      // Decode and marshall the response from the IdP
      ResponseDocument responseDocument = ResponseDocument.Factory.parse(new StringReader(Utils.decodeBase64(b64SAMLResponse)));
      String idpProviderId = responseDocument.getResponse().getIssuer().getStringValue();

      // Do the trust
      EntityFarm farm = (EntityFarm)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
      EntityManager manager = farm.getEntityManagerForID(idpProviderId);
      X509Certificate x509 = TrustUtils.getX509CertFromSignature(responseDocument);
      if (x509 != null) {
        Metadata idpMetadata = manager.getMetadata(idpProviderId);
        if (!manager.getTrustEngine().trustEntity(idpMetadata, x509)) {
          throw new GuanxiException("Trust failed");
        }
      }
      else {
        throw new GuanxiException("No X509 from connection");
      }

      HashMap<String, String> namespaces = new HashMap<String, String>();
      namespaces.put(SAML.NS_SAML_20_PROTOCOL, SAML.NS_PREFIX_SAML_20_PROTOCOL);
      namespaces.put(SAML.NS_SAML_20_ASSERTION, SAML.NS_PREFIX_SAML_20_ASSERTION);
      XmlOptions xmlOptions = new XmlOptions();
      xmlOptions.setSavePrettyPrint();
      xmlOptions.setSavePrettyPrintIndent(2);
      xmlOptions.setUseDefaultNamespace();
      xmlOptions.setSaveAggressiveNamespaces();
      xmlOptions.setSaveSuggestedPrefixes(namespaces);
      xmlOptions.setSaveNamespacesFirst();

      // For decryption, we need to be in DOM land
      Document rawSAMLResponseDoc = (Document)responseDocument.newDomNode(xmlOptions);

      /* XMLBeans doesn't give us access to the embedded encryption key for some reason
       * so we need to break out to DOM and back again.
       */
      EncryptedKeyDocument encKeyDoc = EncryptedKeyDocument.Factory.parse(responseDocument.getResponse().getEncryptedAssertionArray(0).getEncryptedData().getKeyInfo().getDomNode().getFirstChild(), xmlOptions);

      /* Load up the Guard's private key. We need this to decrypt the secret key
       * which was used to encrypt the attributes.
       */
      KeyStore guardKeystore = KeyStore.getInstance("JKS");
      GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);
      FileInputStream fis = new FileInputStream(guardNativeMetadata.getKeystore());
      guardKeystore.load(fis, guardNativeMetadata.getKeystorePassword().toCharArray());
      fis.close();
      PrivateKey privateKey = (PrivateKey)guardKeystore.getKey(guardEntityDescriptor.getEntityID(), guardNativeMetadata.getKeystorePassword().toCharArray());

      // Get a handle on the encypted data in DOM land
      String namespaceURI = EncryptionConstants.EncryptionSpecNS;
      String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;
      Element encryptedDataElement = (Element)rawSAMLResponseDoc.getElementsByTagNameNS(namespaceURI, localName).item(0);

      /* This block unwraps and decrypts the secret key. The IdP first encrypts the attributes
       * using a secret key. It then encrypts that secret key using the public key of the Guard.
       * So the first step is to use the Guard's private key to decrypt the secret key.
       */
      String algorithm = encKeyDoc.getEncryptedKey().getEncryptionMethod().getAlgorithm();
      XMLCipher xmlCipher = XMLCipher.getInstance();
      xmlCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
      EncryptedData encryptedData = xmlCipher.loadEncryptedData(rawSAMLResponseDoc, encryptedDataElement);
      EncryptedKey encryptedKey = encryptedData.getKeyInfo().itemEncryptedKey(0);
      Key decryptedSecretKey = xmlCipher.decryptKey(encryptedKey, algorithm);

      // This block uses the decrypted secret key to decrypt the attributes
      Key secretKey = new SecretKeySpec(decryptedSecretKey.getEncoded(), "AES");
      XMLCipher xmlDecryptCipher = XMLCipher.getInstance();
      xmlDecryptCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
      xmlDecryptCipher.doFinal(rawSAMLResponseDoc, encryptedDataElement);

      // And back to XMLBeans for that nice API!
      responseDocument = ResponseDocument.Factory.parse(rawSAMLResponseDoc);
    }
    catch(XmlException xe) {
      logger.error(xe);
    }
    catch(XMLEncryptionException xee) {
      logger.error(xee);
    }
    catch(Exception e) {
      logger.error(e);
    }
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
  public void setPodderView(String podderView) { this.podderView = podderView; }
  public void setErrorView(String errorView) { this.errorView = errorView; }
  public void setErrorViewDisplayVar(String errorViewDisplayVar) { this.errorViewDisplayVar = errorViewDisplayVar; }




  private void dumpSAML(org.guanxi.xal.saml_2_0.protocol.ResponseDocument samlResponseDoc) {
    // Sort out the namespaces for saving the Response
    HashMap<String, String> namespaces = new HashMap<String, String>();
    namespaces.put(SAML.NS_SAML_20_PROTOCOL, SAML.NS_PREFIX_SAML_20_PROTOCOL);
    namespaces.put(SAML.NS_SAML_20_ASSERTION, SAML.NS_PREFIX_SAML_20_ASSERTION);
    XmlOptions xmlOptions = new XmlOptions();
    xmlOptions.setSavePrettyPrint();
    xmlOptions.setSavePrettyPrintIndent(2);
    xmlOptions.setUseDefaultNamespace();
    xmlOptions.setSaveAggressiveNamespaces();
    xmlOptions.setSaveSuggestedPrefixes(namespaces);
    xmlOptions.setSaveNamespacesFirst();

    StringWriter sw = new StringWriter();
    try {
      samlResponseDoc.save(sw, xmlOptions);
    }
    catch(IOException ioe) {
      // Do I care?
    }

    logger.debug(sw.toString());
  }
}
