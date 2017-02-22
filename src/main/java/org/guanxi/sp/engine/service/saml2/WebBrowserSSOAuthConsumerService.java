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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.xerces.util.URI;
import org.apache.xerces.util.URI.MalformedURIException;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.guanxi.common.Bag;
import org.guanxi.common.EntityConnection;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Utils;
import org.guanxi.common.definitions.EduPerson;
import org.guanxi.common.definitions.EduPersonOID;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.definitions.SAML;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.common.trust.TrustUtils;
import org.guanxi.sp.Util;
import org.guanxi.sp.engine.Config;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.assertion.AssertionDocument;
import org.guanxi.xal.saml_2_0.assertion.AssertionType;
import org.guanxi.xal.saml_2_0.assertion.AttributeStatementType;
import org.guanxi.xal.saml_2_0.assertion.AttributeType;
import org.guanxi.xal.saml_2_0.assertion.EncryptedElementType;
import org.guanxi.xal.saml_2_0.assertion.NameIDDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.protocol.ResponseDocument;
import org.guanxi.xal.w3.xmlenc.EncryptedKeyDocument;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Handles the trust and attribute decryption for SAML2 Web Browser SSO profile.
 * 
 * @author alistair
 */
public class WebBrowserSSOAuthConsumerService extends MultiActionController
		implements ServletContextAware {
	/** Our logger */
	protected static final Logger logger = Logger
			.getLogger(WebBrowserSSOAuthConsumerService.class.getName());
	/** Whether to dump the incoming response to the log */
	private boolean logResponse = false;
	/** Add a Subject/NameID to the bag of attributes under this name */
	private String subjectNameIDAttributeName = null;
	/** If we allow unsolicited responses */
	private boolean allowUnsolicited = false;

	public void init() {
	}

	public void destroy() {
	}

	/**
	 * This is the handler for the initial /s2/wbsso/acs page. This receives the
	 * browser after it has visited the IdP.
	 * 
	 * @param request
	 *            ServletRequest
	 * @param response
	 *            ServletResponse
	 * @throws java.io.IOException
	 *             if an error occurs
	 * @throws org.guanxi.common.GuanxiException
	 *             if an error occurs
	 * @throws java.security.KeyStoreException
	 *             if an error occurs
	 * @throws java.security.NoSuchAlgorithmException
	 *             if an error occurs
	 * @throws java.security.cert.CertificateException
	 *             if an error occurs
	 */
	public void acs(HttpServletRequest request, HttpServletResponse response)
			throws IOException, GuanxiException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException {
		String relayState = request.getParameter("RelayState");
		String b64SAMLResponse = request.getParameter("SAMLResponse");
		EntityDescriptorType guardEntityDescriptor = null;
		String guardSession = null;
		boolean unsolicitedMode = false;

		logger.info("Received RelayState: " + relayState);

		if (allowUnsolicited && checkForUnsolicited(request, relayState)) {
			if (!StringUtils.hasText(relayState)) {
				response.setContentType("text/html");
				PrintWriter out = response.getWriter();
				out.println("Metadata error<br /><br />");
				out.println("Not a valid unsolitied session");
				out.flush();
				out.close();
				return;
			}

			unsolicitedMode = true;
			guardEntityDescriptor = getUnsolicitedGuard(request, relayState);
			guardSession = getTargetResource(request, relayState);
			
			logger.info("Processing unsolicited request for guardSession:" + guardSession);
		} else {
			if (StringUtils.hasText(relayState) && (getServletContext().getAttribute(
					relayState.replaceAll("GUARD", "ENGINE")) == null)) {
				response.setContentType("text/html");
				PrintWriter out = response.getWriter();
				out.println("Metadata error<br /><br />");
				out.println("Not a valid session");
				out.flush();
				out.close();
				return;
			}

			// We previously changed the Guard session ID to an Engine one...
			guardEntityDescriptor = (EntityDescriptorType) getServletContext()
					.getAttribute(relayState.replaceAll("GUARD", "ENGINE"));
			// ...so now change it back as it will be passed to the Guard
			guardSession = relayState.replaceAll("ENGINE", "GUARD");
			
			logger.info("Processing request for guardSession:" + guardSession);
		}

		try {
			// Decode and unmarshall the response from the IdP
			ResponseDocument responseDocument = null;
			if (request.getMethod().equalsIgnoreCase("post")) {
				responseDocument = ResponseDocument.Factory
						.parse(new StringReader(Utils
								.decodeBase64(b64SAMLResponse)));
			} else {
				byte[] decodedRequest = Utils.decodeBase64b(b64SAMLResponse);
				responseDocument = ResponseDocument.Factory.parse(Utils
						.inflate(decodedRequest, Utils.RFC1951_NO_WRAP));
			}

			if (logResponse) {
				logger.info("=======================================================");
				logger.info("IdP response from providerId " + 
						responseDocument.getResponse().getIssuer().getStringValue());
				logger.info("");
				StringWriter sw = new StringWriter();
				responseDocument.save(sw, getXMLOptions());
				logger.info(sw.toString());
				sw.close();
				logger.info("");
				logger.info("=======================================================");
			}

			checkTrust(responseDocument);

			GuardRoleDescriptorExtensions guardNativeMetadata = Util
					.getGuardNativeMetadata(guardEntityDescriptor);

			// Decrypt the response if required
			if (TrustUtils.isEncrypted(responseDocument)) {
				try {
					responseDocument = decryptResponse(responseDocument, 
							guardEntityDescriptor.getEntityID(),
							guardNativeMetadata);
				} catch (GuanxiException ge) {
					response.setContentType("text/html");
					PrintWriter out = response.getWriter();
					out.println("Decryption error<br /><br />");
					out.println(ge.getMessage());
					out.flush();
					out.close();
					return;
				}
			}

			Config config = (Config) getServletContext().getAttribute(
					Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);
			guardSession = processGuardConnection(
					guardEntityDescriptor.getEntityID(), guardNativeMetadata,
					config, responseDocument, guardSession, unsolicitedMode);

			response.sendRedirect(getPodderURL(guardSession, config,
					guardNativeMetadata) + "?id=" + guardSession);

			/*
			 * Stop replay attacks. If another message comes in with the same
			 * RelayState we won't be able to find the Guard metadata it refers
			 * to as we've deleted it.
			 */
			getServletContext().removeAttribute(
					guardSession.replaceAll("GUARD", "ENGINE"));
		} catch (XmlException xe) {
			logger.error("Exception: ",xe);
		} catch (Exception e) {
			logger.error("Exception: ",e);
		}
	}
	
	protected XmlOptions getXMLOptions()
	{
		HashMap<String, String> namespaces = new HashMap<String, String>();
		namespaces.put(SAML.NS_SAML_20_PROTOCOL,
				SAML.NS_PREFIX_SAML_20_PROTOCOL);
		namespaces.put(SAML.NS_SAML_20_ASSERTION,
				SAML.NS_PREFIX_SAML_20_ASSERTION);
		XmlOptions xmlOptions = new XmlOptions();
		xmlOptions.setSavePrettyPrint();
		xmlOptions.setSavePrettyPrintIndent(2);
		xmlOptions.setUseDefaultNamespace();
		xmlOptions.setSaveAggressiveNamespaces();
		xmlOptions.setSaveSuggestedPrefixes(namespaces);
		xmlOptions.setSaveNamespacesFirst();
		
		return xmlOptions;
	}

	protected void checkTrust(ResponseDocument responseDocument) throws GuanxiException {
		logger.debug("checkTrust: entry");
		// Do the trust
		if (responseDocument.getResponse().getSignature() != null ||
				(!TrustUtils.isEncrypted(responseDocument) && responseDocument.getResponse().getAssertionArray(0).getSignature() != null)) {
			String idpProviderId = responseDocument.getResponse().getIssuer().getStringValue();
			
			if (!TrustUtils.verifySignature(responseDocument)) {
				throw new GuanxiException("Trust failed");
			}
			EntityFarm farm = (EntityFarm) getServletContext().getAttribute(
					Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
			EntityManager manager = farm.getEntityManagerForID(idpProviderId);
			X509Certificate x509 = TrustUtils
					.getX509CertFromSignature(responseDocument);
			if (x509 != null) {
				Metadata idpMetadata = manager.getMetadata(idpProviderId);
				if (!manager.getTrustEngine().trustEntity(idpMetadata, x509)) {
					throw new GuanxiException("Trust failed");
				}
			} else {
				throw new GuanxiException("No X509 from signature");
			}
		}
		else
		{
			logger.warn("checkTrust: found no signature in response");
		}
		
		logger.debug("checkTrust: exit");
	}

	protected String getTargetResource(HttpServletRequest request, String relayState) {
		return relayState;
	}

	protected EntityDescriptorType getUnsolicitedGuard(HttpServletRequest request, String relayState)
			throws MalformedURIException, GuanxiException {
		URI uri = new URI(relayState);
		return (EntityDescriptorType) getServletContext().getAttribute(
				getQueryMap(uri.getQueryString()).get("sp"));
	}

	protected static Map<String, String> getQueryMap(String query) {
		Map<String, String> map = new HashMap<String, String>();

		if (query != null) {
			String[] params = query.split("&");

			logger.debug("Parsing query map: " + params.length);

			for (String param : params) {
				String name = param.split("=")[0];
				String value = param.split("=")[1];
				map.put(name, value);
			}
		}

		return map;
	}

	private boolean checkForUnsolicited(HttpServletRequest request, String relayState) throws GuanxiException {
		// for now check if the relaystate is a session id
		return relayState != null && !relayState.contains("GUARD")
				&& !relayState.contains("ENGINE");
	}

	/**
	 * Opportunity for extending classes to do some work to generate the podder
	 * URL
	 * 
	 */
	protected String getPodderURL(String sessionID, Config config,
			GuardRoleDescriptorExtensions guardNativeMetadata)
			throws GuanxiException {
		return guardNativeMetadata.getPodderURL();
	}

	private String processGuardConnection(String entityID,
			GuardRoleDescriptorExtensions guardNativeMetadata, Config config,
			ResponseDocument responseDocument, String guardSession,
			boolean unsolicitedMode) throws GuanxiException, IOException {
		EntityConnection connection;

		Bag bag = getBag(responseDocument, guardSession, unsolicitedMode);

		// Initialise the connection to the Guard's attribute consumer service
		connection = new EntityConnection(
				guardNativeMetadata.getAttributeConsumerServiceURL(), entityID,
				guardNativeMetadata.getKeystore(),
				guardNativeMetadata.getKeystorePassword(),
				config.getTrustStore(), config.getTrustStorePassword(),
				EntityConnection.PROBING_OFF);
		connection.setDoOutput(true);
		connection.connect();
		
		if(logger.isDebugEnabled()) {
			logger.debug("bag:" + bag.toJSON());
		}

		// Send the data to the Guard in an explicit POST variable
		String json = URLEncoder.encode(
				Guanxi.REQUEST_PARAMETER_SAML_ATTRIBUTES, "UTF-8")
				+ "="
				+ URLEncoder.encode(bag.toJSON(), "UTF-8");

		OutputStreamWriter wr = new OutputStreamWriter(
				connection.getOutputStream());
		wr.write(json);
		wr.flush();
		wr.close();

		// os.close();

		// ...and read the response from the Guard
		String returnedSessionID = new String(Utils.read(connection.getInputStream()));

		if (!bag.isUnsolicitedMode()) {
			if (!returnedSessionID.equals(guardSession)) {
				throw new GuanxiException(
						"Guards session id does not match working session id");
			}
		}

		return returnedSessionID;

	}

	/**
	 * Constructs a Bag of attributes from the SAML Response
	 * 
	 * @param responseDocument
	 *            The SAML Response containing the attributes
	 * @param guardSession
	 *            the Guard's session ID
	 * @return Bag of attributes
	 * @throws GuanxiException
	 *             if an error occurred
	 */
	private Bag getBag(ResponseDocument responseDocument, String guardSession,
			boolean unsolicitedMode) throws GuanxiException {
		Bag bag = new Bag();
		bag.setSessionID(guardSession);
		bag.setUnsolicitedMode(unsolicitedMode);

		try {
			bag.setSamlResponse(Utils.base64(responseDocument.toString().getBytes()));

			AssertionType[] assertions = null;
			if (TrustUtils.isEncrypted(responseDocument)) {
				assertions = getAssertionsFromDecryptedResponse(responseDocument);
			} else {
				assertions = responseDocument.getResponse().getAssertionArray();
			}

			for (AssertionType assertion : assertions) {
				if (assertion.getAttributeStatementArray().length == 0) {
					// No attributes available
					return bag;
				}

				if (assertion.getSubject() != null) {
					if (assertion.getSubject().getNameID() != null) {
						bag.addAttribute(subjectNameIDAttributeName, assertion
								.getSubject().getNameID().getStringValue());
					}
				}

				AttributeStatementType attributeStatement = assertion
						.getAttributeStatementArray(0);
				AttributeType[] attributes = attributeStatement
						.getAttributeArray();

				String attributeOID = null;
				for (AttributeType attribute : attributes) {
					if (attribute.getNameFormat() == null || //change to support O365
							attribute.getNameFormat().equals(
									SAML.SAML2_ATTRIBUTE_PROFILE_BASIC)) {
						XmlObject[] attributeValues = attribute
								.getAttributeValueArray();
						for (int cc = 0; cc < attributeValues.length; cc++) {
							String attrValue = attributeValues[cc].getDomNode()
									.getFirstChild().getNodeValue();
							bag.addAttribute(attribute.getName(), attrValue);
						}
					} else if (attribute.getNameFormat().equals(
							SAML.SAML2_ATTRIBUTE_PROFILE_X500_LDAP)) {
						// Remove the prefix from the attribute name
						attributeOID = attribute.getName().replaceAll(
								EduPersonOID.ATTRIBUTE_NAME_PREFIX, "");

						XmlObject[] attributeValues = attribute
								.getAttributeValueArray();
						for (int cc = 0; cc < attributeValues.length; cc++) {
							// Is it a scoped attribute?
							if (attributeValues[cc]
									.getDomNode()
									.getAttributes()
									.getNamedItem(
											EduPerson.EDUPERSON_SCOPE_ATTRIBUTE) != null) {
								String attrValue = attributeValues[cc]
										.getDomNode().getFirstChild()
										.getNodeValue();
								attrValue += EduPerson.EDUPERSON_SCOPED_DELIMITER;
								attrValue += attributeValues[cc]
										.getDomNode()
										.getAttributes()
										.getNamedItem(
												EduPerson.EDUPERSON_SCOPE_ATTRIBUTE)
										.getNodeValue();
								if (attributeHasFriendlyName(attribute)) {
									bag.addAttribute(
											attribute.getFriendlyName(),
											attrValue);
								}
								bag.addAttribute(attribute.getName(), attrValue);
								
								if(!attribute.getName().equals(attributeOID)) {
									bag.addAttribute(attributeOID, attrValue);
								}
							}
							// What about eduPersonTargetedID?
							else if (attributeOID
									.equals(EduPersonOID.OID_EDUPERSON_TARGETED_ID)) {
								NodeList attrValueNodes = attributeValues[cc]
										.getDomNode().getChildNodes();
								Node attrValueNode = null;
								for (int c = 0; c < attrValueNodes.getLength(); c++) {
									attrValueNode = attrValueNodes.item(c);
									if (attrValueNode.getLocalName() != null) {
										if (attrValueNode.getLocalName()
												.equals("NameID"))
											break;
									}
								}
								if (attrValueNode != null) {
									NameIDDocument nameIDDoc = NameIDDocument.Factory
											.parse(attrValueNode);
									if (attributeHasFriendlyName(attribute)) {
										bag.addAttribute(attribute
												.getFriendlyName(), nameIDDoc
												.getNameID().getStringValue());
									}
									bag.addAttribute(attribute.getName(),
											nameIDDoc.getNameID()
													.getStringValue());
									bag.addAttribute(attributeOID, nameIDDoc
											.getNameID().getStringValue());
									bag.addAttribute("namequalifier", nameIDDoc
											.getNameID().getNameQualifier());
									bag.addAttribute("spnamequalifier",
											nameIDDoc.getNameID()
													.getSPNameQualifier());
								}
							} else {
								if (attributeValues[cc].getDomNode()
										.getFirstChild() != null) {
									if (attributeValues[cc].getDomNode()
											.getFirstChild().getNodeValue() != null) {
										if (attributeHasFriendlyName(attribute)) {
											bag.addAttribute(
													attribute.getFriendlyName(),
													attributeValues[cc]
															.getDomNode()
															.getFirstChild()
															.getNodeValue());
										}
										bag.addAttribute(attribute.getName(),
												attributeValues[cc]
														.getDomNode()
														.getFirstChild()
														.getNodeValue());
										
										if(!attribute.getName().equals(attributeOID)) {
											bag.addAttribute(attributeOID,
													attributeValues[cc]
															.getDomNode()
															.getFirstChild()
															.getNodeValue());
										}
									}
								}
							}
						} // for (int cc=0; cc < obj.length; cc++)
					} // else if
						// (attribute.getNameFormat().equals(SAML.SAML2_ATTRIBUTE_PROFILE_X500_LDAP))
						// {
				} // for (AttributeType attribute : attributes)
			} // for (EncryptedElementType assertion : assertions)

			return bag;
		} catch (XmlException xe) {
			throw new GuanxiException(xe);
		}
	}

	/**
	 * Determines whether an Attribute has a FriendlyName
	 * 
	 * @param attribute
	 *            the Attribute
	 * @return true if it has a FriendlyName, otherwise false
	 */
	private boolean attributeHasFriendlyName(AttributeType attribute) {
		return ((attribute.getFriendlyName() != null) && (attribute
				.getFriendlyName().length() > 0));
	}

	/**
	 * Extracts the Assertions from a decrypted SAML2 Response
	 * 
	 * @param decryptedResponse
	 *            the Response which contains the Assertions
	 * @return array of AssertionType objects or null
	 */
	private AssertionType[] getAssertionsFromDecryptedResponse(
			ResponseDocument decryptedResponse) {
		try {
			ArrayList<AssertionType> assertions = new ArrayList<AssertionType>();

			EncryptedElementType[] encryptedElements = decryptedResponse
					.getResponse().getEncryptedAssertionArray();

			for (EncryptedElementType encryptedElement : encryptedElements) {
				NodeList nodes = encryptedElement.getDomNode().getChildNodes();
				Node assertionNode = null;
				for (int c = 0; c < nodes.getLength(); c++) {
					assertionNode = nodes.item(c);
					if (assertionNode.getLocalName() != null) {
						if (assertionNode.getLocalName().equals("Assertion")) {
							assertions.add(AssertionDocument.Factory.parse(
									assertionNode).getAssertion());
						}
					}
				}
				if (assertionNode == null) {
					continue;
				}
			}

			return assertions.toArray(new AssertionType[assertions.size()]);
		} catch (XmlException xe) {
			return null;
		}
	}

	/**
	 * Decrypts a SAML2 Web Browser SSO Response from an IdP
	 * 
	 * @param encryptedResponse
	 *            The encrypted Response
	 * @param xmlOptions
	 *            XmlOptions describing namesapces in the Response
	 * @param privateKey
	 *            the Guard's private key used to decrypt the Response
	 * @return decrypted Response
	 */
	protected ResponseDocument decryptResponse(
			ResponseDocument encryptedResponse,
			String entityId, GuardRoleDescriptorExtensions guardNativeMetadata)
			throws GuanxiException {
		try {

			/*
			 * Load up the Guard's private key. We need this to decrypt the
			 * secret key which was used to encrypt the attributes.
			 */

			XmlOptions xmlOptions = getXMLOptions();
			KeyStore guardKeystore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(guardNativeMetadata.getKeystore());
			guardKeystore.load(fis, guardNativeMetadata.getKeystorePassword().toCharArray());
			fis.close();
			PrivateKey guardPrivateKey = (PrivateKey) guardKeystore.getKey(
					entityId, guardNativeMetadata.getKeystorePassword().toCharArray());

			// For decryption, we need to be in DOM land
			Document rawSAMLResponseDoc = (Document) encryptedResponse.newDomNode(xmlOptions);

			/*
			 * XMLBeans doesn't give us access to the embedded encryption key
			 * for some reason so we need to break out to DOM and back again.
			 */
			NodeList nodes = encryptedResponse.getResponse()
					.getEncryptedAssertionArray(0).getEncryptedData()
					.getKeyInfo().getDomNode().getChildNodes();
			Node node = null;
			for (int c = 0; c < nodes.getLength(); c++) {
				node = nodes.item(c);
				if (node.getLocalName() != null) {
					if (node.getLocalName().equals("EncryptedKey"))
						break;
				}
			}
			EncryptedKeyDocument encKeyDoc = EncryptedKeyDocument.Factory.parse(node, xmlOptions);

			// Get a handle on the encypted data in DOM land
			String namespaceURI = EncryptionConstants.EncryptionSpecNS;
			String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;

			// Recurse through the decryption process
			NodeList encyptedDataNodes = rawSAMLResponseDoc
					.getElementsByTagNameNS(namespaceURI, localName);
			while (encyptedDataNodes.getLength() > 0) {
				Element encryptedDataElement = (Element) encyptedDataNodes.item(0);

				/*
				 * This block unwraps and decrypts the secret key. The IdP first
				 * encrypts the attributes using a secret key. It then encrypts
				 * that secret key using the public key of the Guard. So the
				 * first step is to use the Guard's private key to decrypt the
				 * secret key.
				 */
				String algorithm = encKeyDoc.getEncryptedKey()
						.getEncryptionMethod().getAlgorithm();
				XMLCipher xmlCipher = XMLCipher.getInstance();
				xmlCipher.init(XMLCipher.UNWRAP_MODE, guardPrivateKey);
				EncryptedData encryptedData = xmlCipher.loadEncryptedData(
						rawSAMLResponseDoc, encryptedDataElement);
				EncryptedKey encryptedKey = encryptedData.getKeyInfo().itemEncryptedKey(0);
				Key decryptedSecretKey = xmlCipher.decryptKey(encryptedKey,algorithm);

				// This block uses the decrypted secret key to decrypt the
				// attributes
				Key secretKey = new SecretKeySpec(
						decryptedSecretKey.getEncoded(), "AES");
				XMLCipher xmlDecryptCipher = XMLCipher.getInstance();
				xmlDecryptCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
				xmlDecryptCipher.doFinal(rawSAMLResponseDoc,encryptedDataElement);

				// Any more encryption to handle?
				encyptedDataNodes = rawSAMLResponseDoc.getElementsByTagNameNS(
						namespaceURI, localName);
			}

			// And back to XMLBeans for that nice API!
			return ResponseDocument.Factory.parse(rawSAMLResponseDoc);
		} catch (XmlException xe) {
			logger.error("XML problem decrypting the response", xe);
			throw new GuanxiException(xe);
		} catch (XMLEncryptionException xee) {
			logger.error("XML problem decrypting the response", xee);
			throw new GuanxiException(xee);
		} catch (Exception e) {
			logger.error("Problem decrypting the response", e);
			throw new GuanxiException(e);
		}
	}

	public void setLogResponse(boolean logResponse) {
		this.logResponse = logResponse;
	}

	public void setAllowUnsolicited(boolean allowUnsolicited) {
		this.allowUnsolicited = allowUnsolicited;
	}

	public void setSubjectNameIDAttributeName(String subjectNameIDAttributeName) {
		this.subjectNameIDAttributeName = subjectNameIDAttributeName;
	}
}
