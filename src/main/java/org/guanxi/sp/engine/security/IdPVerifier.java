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

package org.guanxi.sp.engine.security;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.context.ServletContextAware;
import org.springframework.context.MessageSource;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.log.Log4JLoggerConfig;
import org.guanxi.common.log.Log4JLogger;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_1_0.protocol.ResponseDocument;
import org.guanxi.xal.saml_1_0.protocol.ResponseType;
import org.guanxi.xal.saml_1_0.assertion.AssertionType;
import org.guanxi.xal.saml_1_0.assertion.AuthenticationStatementType;
import org.guanxi.xal.w3.xmldsig.SignatureType;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.sp.engine.X509Chain;
import org.guanxi.sp.engine.Config;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletContext;
import java.io.StringReader;

/**
 * Security interceptor that verifies whether the Engine will trust the IdentityProvider
 * that is sending an AuthenticationStatement to the Engine.
 * The interceptor will use the metadata registered with the Engine to make this decision.
 */
public class IdPVerifier extends HandlerInterceptorAdapter implements ServletContextAware {
  /** The ServletContext, passed to us by Spring as we are ServletContextAware */
  private ServletContext servletContext = null;
  /** Our logger */
  private Logger log = null;
  /** The logger config */
  private Log4JLoggerConfig loggerConfig = null;
  /** The Logging setup to use */
  private Log4JLogger logger = null;
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
    try {
      loggerConfig.setClazz(IdPVerifier.class);

      // Sort out the file paths for logging
      loggerConfig.setLogConfigFile(servletContext.getRealPath(loggerConfig.getLogConfigFile()));
      loggerConfig.setLogFile(servletContext.getRealPath(loggerConfig.getLogFile()));

      // Get our logger
      log = logger.initLogger(loggerConfig);
    }
    catch(GuanxiException ge) {
    }
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
      // Parse the SAML Response containing the AuthenticationStatement coming from the IdP
      responseDocument = ResponseDocument.Factory.parse(new StringReader(Utils.decodeBase64(request.getParameter("SAMLResponse"))));

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
      log.error("Could not process the AuthenticatonStatement from the IdP", e);
      request.setAttribute("error", messages.getMessage("engine.error.cannot.parse.authnstmnt", null, request.getLocale()));
      request.setAttribute("message", e.getMessage());
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    /* Find the IdP's metadata from our store. This is based on it's providerId, which is matched
     * against the entityID in the IdP's EntityDescriptor file.
     */
    EntityDescriptorType idpMetadata = (EntityDescriptorType)servletContext.getAttribute(idpProviderID);
    if (idpMetadata == null) {
      log.error("Could not find IdP '" + idpProviderID + "' in the metadata repository");
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
      log.error("No signature from IdP");
      request.setAttribute("error", messages.getMessage("engine.error.no.idp.signtaure", null, request.getLocale()));
      request.setAttribute("message", idpProviderID);
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    // Do we trust the IdP's certificate issuer?
    KeyInfoType keyInfoType = sigType.getKeyInfo();
    X509Chain x509Chain = (X509Chain)servletContext.getAttribute(Guanxi.CONTEXT_ATTR_X509_CHAIN);
    if (!x509Chain.verifyChain(keyInfoType)) {
      log.error("Can't find a certificate for the IdP");
      request.setAttribute("error", messages.getMessage("engine.error.idp.sig.failed.verification", null, request.getLocale()));
      request.setAttribute("message", idpProviderID);
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    return true;
  }

  public void setLoggerConfig(Log4JLoggerConfig loggerConfig) { this.loggerConfig = loggerConfig; }
  public Log4JLoggerConfig getLoggerConfig() { return loggerConfig; }

  public void setLogger(Log4JLogger logger) { this.logger = logger; }
  public Log4JLogger getLogger() { return logger; }

  public void setMessages(MessageSource messages) { this.messages = messages; }
  
  public void setErrorPage(String errorPage) { this.errorPage = errorPage; }
}
