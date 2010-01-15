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
import org.apache.log4j.Logger;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.EntityConnection;
import org.guanxi.common.GuanxiException;
import org.guanxi.sp.Util;
import org.guanxi.sp.engine.Config;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Verification process for a Guard
 */
public class GuardVerifier extends HandlerInterceptorAdapter implements ServletContextAware {
  private static final Logger logger = Logger.getLogger(GuardVerifier.class.getName());

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
   * Blocks Guard access to a service until the Guard can be verified.
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletResponse
   * @param object handler
   * @return true if the caller is authorised to use the service
   * @throws Exception if an error occurs
   */
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object object) throws Exception {
    String guardID  = request.getParameter(Guanxi.WAYF_PARAM_GUARD_ID);
    String sessionID = request.getParameter(Guanxi.WAYF_PARAM_SESSION_ID);

    if ((guardID == null) || (sessionID == null)) {
      logger.error("Cant' verify Guard due to missing parameter");
      request.setAttribute("error", messages.getMessage("engine.error.missing.guard.verification.parameter", null, request.getLocale()));
      request.setAttribute("message", messages.getMessage("engine.error.missing.guard.verification.parameter", null, request.getLocale()));
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)servletContext.getAttribute(guardID);
    if (guardEntityDescriptor == null) {
      logger.error("Guard '" + guardID + "' not found in metadata repository");
      request.setAttribute("error", messages.getMessage("engine.error.no.guard.metadata", null, request.getLocale()));
      request.setAttribute("message", messages.getMessage("engine.error.no.guard.metadata", null, request.getLocale()));
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    Config config = (Config)servletContext.getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);
    if (config == null) {
      logger.error("Guard '" + guardID + "' wants to talk but Engine hasn't finished initialisation");
      request.setAttribute("error", messages.getMessage("engine.error.not.initialised", null, request.getLocale()));
      request.setAttribute("message", messages.getMessage("engine.error.not.initialised", null, request.getLocale()));
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    // Load the GuanxiGuardService node from the metadata
    GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);

    // Build the REST URL to verify the Guard's session
    String queryString = guardNativeMetadata.getVerifierURL() + "?" +
                         Guanxi.SESSION_VERIFIER_PARAM_SESSION_ID + "=" +
                         sessionID;

    // If we haven't already checked the Guard for secure comms, do it now
    if (servletContext.getAttribute(guardID + "SECURE_CHECK_DONE_SP") == null) {
      // Load up the Guard's native metadata...
      GuardRoleDescriptorExtensions guardExt = Util.getGuardNativeMetadata(guardEntityDescriptor);

      // ...and see if it's using HTTPS
      try {
        if (Util.isGuardSecure(guardExt)) {
          logger.info("Probing for Guard certificate for : " + guardID);

          /* If the Guard is using HTTPS then we'll need to connect to it, extract it's
           * certificate and add it to our truststore. To do that, we'll need to use our
           * own keystore to let the Guard authenticate us.
           */
          EntityConnection guardConnection = new EntityConnection(queryString,
                                                                  config.getCertificateAlias(), // alias of cert
                                                                  config.getKeystore(),
                                                                  config.getKeystorePassword(),
                                                                  config.getTrustStore(),
                                                                  config.getTrustStorePassword(),
                                                                  EntityConnection.PROBING_ON);
          X509Certificate guardX509 = guardConnection.getServerCertificate();

          // We've got the Guard's X509 so add it to our truststore...
          KeyStore engineTrustStore = KeyStore.getInstance("jks");
          engineTrustStore.load(new FileInputStream(config.getTrustStore()),
                                config.getTrustStorePassword().toCharArray());
          // ...under it's Subject DN as an alias...
          engineTrustStore.setCertificateEntry(guardID, guardX509);
          // ...and rewrite the trust store
          engineTrustStore.store(new FileOutputStream(config.getTrustStore()),
                                 config.getTrustStorePassword().toCharArray());

          // Mark Guard as having been checked for secure comms
          servletContext.setAttribute(guardID + "SECURE_CHECK_DONE_SP", "SECURE");

          logger.info("Added : " + guardID + " to truststore");
        }
        else {
          // Mark Guard as having been checked for secure comms
          servletContext.setAttribute(guardID + "SECURE_CHECK_DONE_SP", "NOT_SECURE");
        }
      }
      catch(Exception e) {
        logger.error("Failed to probe Guard : " + guardID + " for cert : ", e);
        request.setAttribute("error", messages.getMessage("engine.error.guard.comms.failed", null, request.getLocale()));
        request.setAttribute("message", messages.getMessage("engine.error.guard.comms.failed", null, request.getLocale()));
        request.getRequestDispatcher(errorPage).forward(request, response);
        return false;
      }
    }

    // Verify that the Guard actually sent the request
    String verificationResult = null;
    try {
      EntityConnection verifierService = new EntityConnection(queryString,
                                                              config.getCertificateAlias(), // alias of cert
                                                              config.getKeystore(),
                                                              config.getKeystorePassword(),
                                                              config.getTrustStore(),
                                                              config.getTrustStorePassword(),
                                                              EntityConnection.PROBING_OFF);
      verifierService.setDoOutput(true);
      verifierService.connect();
      verificationResult = verifierService.getContentAsString();
    }
    catch(GuanxiException ge) {
      logger.error("Guard '" + guardID + "' error during verification : ", ge);
      request.setAttribute("error", messages.getMessage("engine.error.guard.comms.failed", null, request.getLocale()));
      request.setAttribute("message", messages.getMessage("engine.error.guard.comms.failed", null, request.getLocale()));
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    // Did the Guard verify the session?
    if (!verificationResult.equals(Guanxi.SESSION_VERIFIER_RETURN_VERIFIED)) {
      logger.error("Guard '" + guardID + "' error during verification : " + verificationResult);
      request.setAttribute("error", messages.getMessage("engine.error.guard.failed.verification", null, request.getLocale()));
      request.setAttribute("message", messages.getMessage("engine.error.guard.failed.verification", null, request.getLocale()));
      request.getRequestDispatcher(errorPage).forward(request, response);
      return false;
    }

    /* Convert the Guard's session ID to an Engine session ID and store the Guard's GuanxiGuardService
     * node under it.
     */
    servletContext.setAttribute(sessionID.replaceAll("GUARD", "ENGINE"), guardEntityDescriptor);

    return true;
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
  public void setErrorPage(String errorPage) { this.errorPage = errorPage; }
}
