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

package org.guanxi.sp.engine.security.shibboleth;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.context.ServletContextAware;
import org.springframework.context.MessageSource;
import org.guanxi.common.Utils;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.definitions.Shibboleth;
import org.guanxi.common.metadata.IdPMetadataManager;
import org.guanxi.common.metadata.IdPMetadata;
import org.guanxi.xal.saml_1_0.protocol.ResponseDocument;
import org.guanxi.xal.saml_1_0.protocol.ResponseType;
import org.guanxi.xal.saml_1_0.assertion.AssertionType;
import org.guanxi.xal.saml_1_0.assertion.AuthenticationStatementType;
import org.guanxi.xal.w3.xmldsig.SignatureType;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.sp.engine.X509Chain;
import org.guanxi.sp.engine.Config;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlOptions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletContext;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.IOException;
import java.util.HashMap;

/**
 * Security interceptor that verifies whether the Engine will trust the IdentityProvider
 * that is sending an AuthenticationStatement to the Engine.
 * The interceptor will use the metadata registered with the Engine to make this decision.
 */
public class IdPVerifier extends HandlerInterceptorAdapter implements ServletContextAware {
  private static final Logger logger = Logger.getLogger(IdPVerifier.class.getName());
  /** The ServletContext, passed to us by Spring as we are ServletContextAware */
  private ServletContext servletContext = null;
  /** The localised messages to use */
  private MessageSource messages = null;
  /** The error page to use */
  private String errorPage = null;

  // Called by Spring as we are ServletContextAware
  public void setServletContext(ServletContext servletContext) { this.servletContext = servletContext; }
  
  /**
   * Initialise the interceptor
   */
  public void init() {
  }

  /**
   * Blocks access to an Engine's REST web service based on resident Engine metadata which defines what
   * entities can access that service.
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletResponse
   * @param object handler
   * @return true if the caller is authorised to use the service
   * @throws Exception if an error occurs
   */
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object object) throws Exception {
    String idpProviderID = null;
    ResponseDocument responseDocument = null;
    ResponseType samlResponse = null;

    try {
      if (request.getParameter("SAMLResponse") == null) {
        logger.error("Could not process the AuthenticatonStatement from the IdP as there isn't one!");
        request.setAttribute("error", messages.getMessage("engine.error.cannot.parse.authnstmnt", null, request.getLocale()));
        request.setAttribute("message", messages.getMessage("engine.error.no.authn.stmnt", null, request.getLocale()));
        request.getRequestDispatcher(errorPage).forward(request, response);
        return false;
      }

      // Parse the SAML Response containing the AuthenticationStatement coming from the IdP
      responseDocument = ResponseDocument.Factory.parse(new StringReader(Utils.decodeBase64(request.getParameter("SAMLResponse"))));

      dumpSAML(responseDocument);

      samlResponse = responseDocument.getResponse();
      AssertionType assertion = samlResponse.getAssertionArray()[0];
      idpProviderID = assertion.getIssuer();
      AuthenticationStatementType authStatement = assertion.getAuthenticationStatementArray()[0];

      request.setAttribute(Config.REQUEST_ATTRIBUTE_SAML_RESPONSE, samlResponse);
      request.setAttribute(Config.REQUEST_ATTRIBUTE_IDP_PROVIDER_ID, idpProviderID);
      request.setAttribute(Config.REQUEST_ATTRIBUTE_IDP_NAME_IDENTIFIER,
                           authStatement.getSubject().getNameIdentifier().getStringValue());
    }
    catch(Exception e) {
      logger.error("Could not process the AuthenticatonStatement from the IdP", e);
      request.setAttribute("error", messages.getMessage("engine.error.cannot.parse.authnstmnt", null, request.getLocale()));
      request.setAttribute("message", e.getMessage());
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    /* Find the IdP's metadata from our store. This is based on it's providerId, which is matched
     * against the entityID in the IdP's EntityDescriptor file.
     */
    IdPMetadata idpMetadata = IdPMetadataManager.getManager().getMetadata(idpProviderID);//(EntityDescriptorType)servletContext.getAttribute(idpProviderID);
    if (idpMetadata == null) {
      logger.error("Could not find IdP '" + idpProviderID + "' in the metadata repository");
      request.setAttribute("error", messages.getMessage("engine.error.no.idp.metadata", null, request.getLocale()));
      request.setAttribute("message", idpProviderID);
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }
    request.setAttribute(Config.REQUEST_ATTRIBUTE_IDP_METADATA, idpMetadata);

    /* We can hit a problem with certs when the IdP's providerId is, e.g. urn:uni:ac:uk:idp
     * but it's cert DN is CN=urn:uni:ac:uk:idp, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
     * We didn't see this in the beginning as the certs generated by BouncyCastle in the IdP don't have
     * the extra OU etc. Most commandline tools do put the extra OU in if you don't specify them.
     *
     * Also, just about anything can be in the subject so the safest method is to find the cert in the
     * SAML Reponse and match it against one that's in the certificate store.
     */
    ResponseType responseType = responseDocument.getResponse();
    SignatureType sigType = responseType.getSignature();

    // If there's no signature on the Response from the IdP, barf
    if (sigType == null) {
      logger.error("No signature from IdP");
      request.setAttribute("error", messages.getMessage("engine.error.no.idp.signtaure", null, request.getLocale()));
      request.setAttribute("message", idpProviderID);
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    // Do we trust the IdP's certificate issuer?
    KeyInfoType keyInfoType = sigType.getKeyInfo();
    X509Chain x509Chain = (X509Chain)servletContext.getAttribute(Guanxi.CONTEXT_ATTR_X509_CHAIN);
    if (!x509Chain.verifyChain(keyInfoType)) {
      logger.error("Can't find a certificate for the IdP");
      request.setAttribute("error", messages.getMessage("engine.error.idp.sig.failed.verification", null, request.getLocale()));
      request.setAttribute("message", idpProviderID);
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    return true;
  }

  /**
   * Dumps the SAML response from the IdP to the logs
   *
   * @param samlResponseDoc Response from the IdP containing the AuthenticationStatement
   */
  private void dumpSAML(ResponseDocument samlResponseDoc) {
    // Sort out the namespaces for saving the Response
    HashMap<String, String> namespaces = new HashMap<String, String>();
    namespaces.put(Shibboleth.NS_SAML_10_PROTOCOL, Shibboleth.NS_PREFIX_SAML_10_PROTOCOL);
    namespaces.put(Shibboleth.NS_SAML_10_ASSERTION, Shibboleth.NS_PREFIX_SAML_10_ASSERTION);
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

  public void setMessages(MessageSource messages) { this.messages = messages; }
  
  public void setErrorPage(String errorPage) { this.errorPage = errorPage; }
}
