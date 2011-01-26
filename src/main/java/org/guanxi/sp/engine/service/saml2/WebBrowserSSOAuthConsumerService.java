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

import org.apache.xmlbeans.XmlObject;
import org.guanxi.common.Bag;
import org.guanxi.common.definitions.EduPerson;
import org.guanxi.common.definitions.EduPersonOID;
import org.guanxi.xal.saml_2_0.assertion.*;
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
import org.guanxi.common.EntityConnection;
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
import org.guanxi.sp.engine.Config;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.net.URLEncoder;

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
  /** Whether to dump the incoming response to the log */
  private boolean logResponse = false;

  public void init() {}

  public void destroy() {}

  /**
   * This is the handler for the initial /s2/wbsso/acs page. This receives the
   * browser after it has visited the IdP.
   *
   * @param request ServletRequest
   * @param response ServletResponse
   * @throws java.io.IOException if an error occurs
   * @throws org.guanxi.common.GuanxiException if an error occurs
   * @throws java.security.KeyStoreException if an error occurs
   * @throws java.security.NoSuchAlgorithmException if an error occurs
   * @throws java.security.cert.CertificateException if an error occurs
   */
  public void acs(HttpServletRequest request, HttpServletResponse response) throws IOException, GuanxiException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    String guardSession = request.getParameter("RelayState");
    String b64SAMLResponse = request.getParameter("SAMLResponse");

    // We previously changed the Guard session ID to an Engine one...
    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardSession.replaceAll("GUARD", "ENGINE"));
    // ...so now change it back as it will be passed to the Guard
    guardSession = guardSession.replaceAll("ENGINE", "GUARD");

    try {
      // Decode and unmarshall the response from the IdP
      String decodedRequest = Utils.decodeBase64(b64SAMLResponse);
      ResponseDocument responseDocument = null;
      if (request.getMethod().equalsIgnoreCase("post")) {
        responseDocument = ResponseDocument.Factory.parse(new StringReader(decodedRequest));
      }
      else {
        responseDocument = ResponseDocument.Factory.parse(Utils.inflate(decodedRequest, Utils.RFC1951_NO_WRAP));
      }
      String idpProviderId = responseDocument.getResponse().getIssuer().getStringValue();

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

      if (logResponse) {
        logger.info("=======================================================");
        logger.info("IdP response from providerId " + idpProviderId);
        logger.info("");
        StringWriter sw = new StringWriter();
        responseDocument.save(sw, xmlOptions);
        logger.info(sw.toString());
        sw.close();
        logger.info("");
        logger.info("=======================================================");
      }

      // Do the trust
      if (responseDocument.getResponse().getSignature() != null) {
        if (!TrustUtils.verifySignature(responseDocument)) {
          throw new GuanxiException("Trust failed");
        }
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
          throw new GuanxiException("No X509 from signature");
        }
      }

      /* Load up the Guard's private key. We need this to decrypt the secret key
       * which was used to encrypt the attributes.
       */
      KeyStore guardKeystore = KeyStore.getInstance("JKS");
      GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);
      FileInputStream fis = new FileInputStream(guardNativeMetadata.getKeystore());
      guardKeystore.load(fis, guardNativeMetadata.getKeystorePassword().toCharArray());
      fis.close();
      PrivateKey guardPrivateKey = (PrivateKey)guardKeystore.getKey(guardEntityDescriptor.getEntityID(), guardNativeMetadata.getKeystorePassword().toCharArray());

      // Decrypt the response if required
      if (isEncrypted(responseDocument)) {
        responseDocument = decryptResponse(responseDocument, xmlOptions, guardPrivateKey);
      }

      Config config = (Config)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);
      processGuardConnection(guardNativeMetadata.getAttributeConsumerServiceURL(),
              guardEntityDescriptor.getEntityID(),
              guardNativeMetadata.getKeystore(),
              guardNativeMetadata.getKeystorePassword(),
              config.getTrustStore(),
              config.getTrustStorePassword(),
              responseDocument,
              guardSession);

      response.sendRedirect(guardNativeMetadata.getPodderURL() + "?id=" + guardSession);
    }
    catch(XmlException xe) {
      logger.error(xe);
    }
    catch(Exception e) {
      logger.error(e);
    }
  }

  private String processGuardConnection(String acsURL, String entityID, String keystoreFile, String keystorePassword,
                                        String truststoreFile, String truststorePassword,
                                        ResponseDocument responseDocument, String guardSession) throws GuanxiException, IOException {
    EntityConnection connection;

    Bag bag = getBag(responseDocument, guardSession);

    // Initialise the connection to the Guard's attribute consumer service
    connection = new EntityConnection(acsURL, entityID,
                                      keystoreFile, keystorePassword,
                                      truststoreFile, truststorePassword,
                                      EntityConnection.PROBING_OFF);
    connection.setDoOutput(true);
    connection.connect();

    // Send the data to the Guard in an explicit POST variable
    String json = URLEncoder.encode(Guanxi.REQUEST_PARAMETER_SAML_ATTRIBUTES, "UTF-8") + "=" + URLEncoder.encode(bag.toJSON(), "UTF-8");

    OutputStreamWriter wr = new OutputStreamWriter(connection.getOutputStream());
    wr.write(json);
    wr.flush();
    wr.close();

    //os.close();

    // ...and read the response from the Guard
    return new String(Utils.read(connection.getInputStream()));
  }


  /**
   * Constructs a Bag of attributes from the SAML Response
   *
   * @param responseDocument The SAML Response containing the attributes
   * @param guardSession the Guard's session ID
   * @return Bag of attributes
   * @throws GuanxiException if an error occurred
   */
  private Bag getBag(ResponseDocument responseDocument, String guardSession) throws GuanxiException {
    Bag bag = new Bag();
    bag.setSessionID(guardSession);
    
    try {
      bag.setSamlResponse(Utils.base64(responseDocument.toString().getBytes()));

      AssertionType[] assertions = null;
      if (isEncrypted(responseDocument)) {
        assertions = getAssertionsFromDecryptedResponse(responseDocument);
      }
      else {
        assertions = responseDocument.getResponse().getAssertionArray();
      }

      for (AssertionType assertion : assertions) {
        if (assertion.getAttributeStatementArray().length == 0) {
          // No attributes available
          return bag;
        }
        AttributeStatementType attributeStatement = assertion.getAttributeStatementArray(0);
        AttributeType[] attributes = attributeStatement.getAttributeArray();

        String attributeOID = null;
        for (AttributeType attribute : attributes) {
          if (attribute.getNameFormat().equals(SAML.SAML2_ATTRIBUTE_PROFILE_BASIC)) {
            XmlObject[] attributeValues = attribute.getAttributeValueArray();
            for (int cc=0; cc < attributeValues.length; cc++) {
              String attrValue = attributeValues[cc].getDomNode().getFirstChild().getNodeValue();
              bag.addAttribute(attribute.getName(), attrValue);
            }
          }
          else if (attribute.getNameFormat().equals(SAML.SAML2_ATTRIBUTE_PROFILE_X500_LDAP)) {
            // Remove the prefix from the attribute name
            attributeOID = attribute.getName().replaceAll(EduPersonOID.ATTRIBUTE_NAME_PREFIX, "");

            XmlObject[] attributeValues = attribute.getAttributeValueArray();
            for (int cc=0; cc < attributeValues.length; cc++) {
              // Is it a scoped attribute?
              if (attributeValues[cc].getDomNode().getAttributes().getNamedItem(EduPerson.EDUPERSON_SCOPE_ATTRIBUTE) != null) {
                String attrValue = attributeValues[cc].getDomNode().getFirstChild().getNodeValue();
                attrValue += EduPerson.EDUPERSON_SCOPED_DELIMITER;
                attrValue += attributeValues[cc].getDomNode().getAttributes().getNamedItem(EduPerson.EDUPERSON_SCOPE_ATTRIBUTE).getNodeValue();
                if (attributeHasFriendlyName(attribute)) {
                  bag.addAttribute(attribute.getFriendlyName(), attrValue);
                }
                bag.addAttribute(attribute.getName(), attrValue);
                bag.addAttribute(attributeOID, attrValue);
              }
              // What about eduPersonTargetedID?
              else if (attributeOID.equals(EduPersonOID.OID_EDUPERSON_TARGETED_ID)) {
                NodeList attrValueNodes = attributeValues[cc].getDomNode().getChildNodes();
                Node attrValueNode = null;
                for (int c=0; c < attrValueNodes.getLength(); c++) {
                  attrValueNode = attrValueNodes.item(c);
                  if (attrValueNode.getLocalName() != null) {
                    if (attrValueNode.getLocalName().equals("NameID"))
                      break;
                  }
                }
                if (attrValueNode != null) {
                  NameIDDocument nameIDDoc = NameIDDocument.Factory.parse(attrValueNode);
                  if (attributeHasFriendlyName(attribute)) {
                    bag.addAttribute(attribute.getFriendlyName(), nameIDDoc.getNameID().getStringValue());
                  }
                  bag.addAttribute(attribute.getName(), nameIDDoc.getNameID().getStringValue());
                  bag.addAttribute(attributeOID, nameIDDoc.getNameID().getStringValue());
                  bag.addAttribute("namequalifier", nameIDDoc.getNameID().getNameQualifier());
                  bag.addAttribute("spnamequalifier", nameIDDoc.getNameID().getSPNameQualifier());
                }
              }
              else {
                if (attributeValues[cc].getDomNode().getFirstChild() != null) {
                  if (attributeValues[cc].getDomNode().getFirstChild().getNodeValue() != null) {
                    if (attributeHasFriendlyName(attribute)) {
                      bag.addAttribute(attribute.getFriendlyName(), attributeValues[cc].getDomNode().getFirstChild().getNodeValue());
                    }
                    bag.addAttribute(attribute.getName(), attributeValues[cc].getDomNode().getFirstChild().getNodeValue());
                    bag.addAttribute(attributeOID, attributeValues[cc].getDomNode().getFirstChild().getNodeValue());
                  }
                }
              }
            } // for (int cc=0; cc < obj.length; cc++)
          } // else if (attribute.getNameFormat().equals(SAML.SAML2_ATTRIBUTE_PROFILE_X500_LDAP)) {
        } // for (AttributeType attribute : attributes)
      } // for (EncryptedElementType assertion : assertions)

      return bag;
    }
    catch(XmlException xe) {
      throw new GuanxiException(xe.getMessage());
    }
  }

  /**
   * Determines whether an Attribute has a FriendlyName
   *
   * @param attribute the Attribute
   * @return true if it has a FriendlyName, otherwise false
   */
  private boolean attributeHasFriendlyName(AttributeType attribute) {
    return ((attribute.getFriendlyName() != null) &&
            (attribute.getFriendlyName().length() > 0));
  }

  /**
   * Extracts the Assertions from a decrypted SAML2 Response
   *
   * @param decryptedResponse the Response which contains the Assertions
   * @return array of AssertionType objects or null
   */
  private AssertionType[] getAssertionsFromDecryptedResponse(ResponseDocument decryptedResponse) {
    try {
      ArrayList<AssertionType> assertions = new ArrayList<AssertionType>();

      EncryptedElementType[] encryptedElements = decryptedResponse.getResponse().getEncryptedAssertionArray();

      for (EncryptedElementType encryptedElement : encryptedElements) {
        NodeList nodes = encryptedElement.getDomNode().getChildNodes();
        Node assertionNode = null;
        for (int c=0; c < nodes.getLength(); c++) {
          assertionNode = nodes.item(c);
          if (assertionNode.getLocalName() != null) {
            if (assertionNode.getLocalName().equals("Assertion")) {
              assertions.add(AssertionDocument.Factory.parse(assertionNode).getAssertion());
            }
          }
        }
        if (assertionNode == null) {
          continue;
        }
      }

      return assertions.toArray(new AssertionType[assertions.size()]);
    }
    catch(XmlException xe) {
      return null;
    }
  }

  /**
   * Determines whether a SAML2 Response is encrypted
   *
   * @param responseDoc the Response to check for encryption
   * @return true if the Response is encrypted, otherwise false
   */
  private boolean isEncrypted(ResponseDocument responseDoc) {
    return ((responseDoc.getResponse().getEncryptedAssertionArray() != null) &&
            (responseDoc.getResponse().getEncryptedAssertionArray().length > 0));
  }

  /**
   * Decrypts a SAML2 Web Browser SSO Response from an IdP
   *
   * @param encryptedResponse The encrypted Response
   * @param xmlOptions XmlOptions describing namesapces in the Response
   * @param privateKey the Guard's private key used to decrypt the Response
   * @return decrypted Response
   */
  private ResponseDocument decryptResponse(ResponseDocument encryptedResponse, XmlOptions xmlOptions, PrivateKey privateKey) {
    try {
      // For decryption, we need to be in DOM land
      Document rawSAMLResponseDoc = (Document)encryptedResponse.newDomNode(xmlOptions);

      /* XMLBeans doesn't give us access to the embedded encryption key for some reason
       * so we need to break out to DOM and back again.
       */
      NodeList nodes = encryptedResponse.getResponse().getEncryptedAssertionArray(0).getEncryptedData().getKeyInfo().getDomNode().getChildNodes();
      Node node = null;
      for (int c=0; c < nodes.getLength(); c++) {
        node = nodes.item(c);
        if (node.getLocalName() != null) {
          if (node.getLocalName().equals("EncryptedKey")) break;
        }
      }
      EncryptedKeyDocument encKeyDoc = EncryptedKeyDocument.Factory.parse(node, xmlOptions);

      // Get a handle on the encypted data in DOM land
      String namespaceURI = EncryptionConstants.EncryptionSpecNS;
      String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;

      // Recurse through the decryption process
      NodeList encyptedDataNodes = rawSAMLResponseDoc.getElementsByTagNameNS(namespaceURI, localName);
      while (encyptedDataNodes.getLength() > 0) {
        Element encryptedDataElement = (Element)encyptedDataNodes.item(0);

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

        // Any more encryption to handle?
        encyptedDataNodes = rawSAMLResponseDoc.getElementsByTagNameNS(namespaceURI, localName);
      }

      // And back to XMLBeans for that nice API!
      return ResponseDocument.Factory.parse(rawSAMLResponseDoc);
    }
    catch(XmlException xe) {
      logger.error("XML problem decrypting the response", xe);
      return null;
    }
    catch(XMLEncryptionException xee) {
      logger.error("XML problem decrypting the response", xee);
      return null;
    }
    catch(Exception e) {
      logger.error("XML problem decrypting the response", e);
      return null;
    }
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
  public void setPodderView(String podderView) { this.podderView = podderView; }
  public void setErrorView(String errorView) { this.errorView = errorView; }
  public void setErrorViewDisplayVar(String errorViewDisplayVar) { this.errorViewDisplayVar = errorViewDisplayVar; }
  public void setLogResponse(boolean logResponse) { this.logResponse = logResponse; }
}
