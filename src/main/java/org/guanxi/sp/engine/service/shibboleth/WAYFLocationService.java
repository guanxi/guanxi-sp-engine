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

package org.guanxi.sp.engine.service.shibboleth;

import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.context.ServletContextAware;

import org.guanxi.common.log.Log4JLogger;
import org.guanxi.common.log.Log4JLoggerConfig;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Errors;
import org.guanxi.common.EntityConnection;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.sp.Util;
import org.guanxi.sp.engine.Config;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.io.FileOutputStream;
import java.io.FileInputStream;

public class WAYFLocationService extends AbstractController implements ServletContextAware {
  /** The marker in our WAYF location map for the one to use as the default location */
  private static final String DEFAULT_WAYF_MARKER = "__DEFAULT__";

  /** Our logger */
  private Logger log = null;
  /** The logger config */
  private Log4JLoggerConfig loggerConfig = null;
  /** The Logging setup to use */
  private Log4JLogger logger = null;
  /** The list of Guard to WAYF location mappings */
  private HashMap<String, String> wayfs = null;
  /** The view page to use */
  private String viewJSP = null;

  public void init() {
    try {
      loggerConfig.setClazz(WAYFLocationService.class);
      
      // Sort out the file paths for logging
      loggerConfig.setLogConfigFile(getServletContext().getRealPath(loggerConfig.getLogConfigFile()));
      loggerConfig.setLogFile(getServletContext().getRealPath(loggerConfig.getLogFile()));

      // Get our logger
      log = logger.initLogger(loggerConfig);
    }
    catch(GuanxiException me) {
    }
  }

  /**
   * Web service endpoint for Guards to obtain the location of the WAYF. A Guard will either get the
   * default WAYF location or one that's specific to that Guard, depending on the settings in:
   * WEB-INF/config/wayf.xml
   *
   * Before the Guard will get the WAYF location, the Engine will send it a message, to which it must
   * respond in the affirmative, to make sure that some other entity is not trying to hijack the Guard's
   * identity.
   *
   * The Engine will load up the Guard's Guanxi metadata and store it under a session attribute that's
   * related to the Guard's session id. When the AuthenticationStatement from an IdP comes to the Engine,
   * the Engine will use the TARGET parameter to load this metadata.
   *
   * Note that there are no localised error messages in this class as it only communicates with the
   * Guard. It's the Guard's job to interpret these system messages and output an appropriate
   * localised message at that end of the connection.
   *
   * @param request Standard HttpServletRequest with the following parameters:
   * guardid
   * sessionid
   *
   * @param response Standard HttpServletResponse
   * query is sent to an AA.
   * @throws Exception if an error occurred
   */
  @SuppressWarnings("unchecked")
  public ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String guardID  = request.getParameter(Guanxi.WAYF_PARAM_GUARD_ID);
    String sessionID = request.getParameter(Guanxi.WAYF_PARAM_SESSION_ID);

    ModelAndView mAndV = new ModelAndView();
    mAndV.setViewName(viewJSP);

    if ((guardID == null) || (sessionID == null)) {
      log.error("Missing param");
      mAndV.getModel().put("wayfLocation", Errors.MISSING_PARAM);
      return mAndV;
    }

    Config config = (Config)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);
    if (config == null) {
      log.error("Guard '" + guardID + "' wants WAYF location but Engine hasn't finished initialisation");
      mAndV.getModel().put("wayfLocation", Errors.ENGINE_CURRENTLY_INITIALISING);
      return mAndV;
    }
    
    // Get the Guard's metadata, previously loaded by the Bootstrapper
    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardID);
    if (guardEntityDescriptor == null) {
      log.error("Guard '" + guardID + "' not found in metadata repository");
      mAndV.getModel().put("wayfLocation", Errors.ENGINE_WAYF_LOCATION_NO_GUARD_ID);
      return mAndV;
    }

    // Load the GuanxiGuardService node from the metadata
    GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);

    // Build the REST URL to verify the Guard's session
    String queryString = guardNativeMetadata.getVerifierURL() + "?" +
                         Guanxi.SESSION_VERIFIER_PARAM_SESSION_ID + "=" +
                         sessionID;

    // If we haven't already checked the Guard for secure comms, do it now
    if (getAttribute(guardID + "SECURE_CHECK_DONE_SP") == null) {
      // Load up the Guard's native metadata...
      GuardRoleDescriptorExtensions guardExt = Util.getGuardNativeMetadata(guardEntityDescriptor);

      // ...and see if it's using HTTPS
      try {
        if (Util.isGuardSecure(guardExt)) {
          log.info("Probing for Guard certificate for : " + guardID);

          /* If the Guard is using HTTPS then we'll need to connect to it, extract it's
           * certificate and add it to our truststore. To do that, we'll need to use our
           * own keystore to let the Guard authenticate us.
           */
          EntityConnection guardConnection = new EntityConnection(queryString,
                                                                  config.getId(), // alias of cert
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
          setAttribute(guardID + "SECURE_CHECK_DONE_SP", "SECURE");

          log.info("Added : " + guardID + " to truststore");
        }
        else {
          // Mark Guard as having been checked for secure comms
          setAttribute(guardID + "SECURE_CHECK_DONE_SP", "NOT_SECURE");
        }
      }
      catch(Exception e) {
        log.error("Failed to probe Guard : " + guardID + " for cert : ", e);
        mAndV.getModel().put("wayfLocation", Errors.GUARD_CERT_PROBE_FAILED);
        return mAndV;
      }
    }

    // Verify that the Guard actually sent the request
    String verificationResult = null;
    try {
      EntityConnection verifierService = new EntityConnection(queryString,
                                                              config.getId(), // alias of cert
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
      log.error("Guard '" + guardID + "' error during verification : ", ge);
      mAndV.getModel().put("wayfLocation", Errors.ENGINE_WAYF_LOCATION_GUARD_FAILED_VERIFICATION);
      return mAndV;
    }

    // Did the Guard verify the session?
    if (!verificationResult.equals(Guanxi.SESSION_VERIFIER_RETURN_VERIFIED)) {
      log.error("Guard '" + guardID + "' error during verification : " + verificationResult);
      mAndV.getModel().put("wayfLocation", Errors.ENGINE_WAYF_LOCATION_GUARD_FAILED_VERIFICATION);
      return mAndV;
    }

    /* Convert the Guard's session ID to an Engine session ID and store the Guard's GuanxiGuardService
     * node under it.
     */
    setAttribute(sessionID.replaceAll("GUARD", "ENGINE"), guardEntityDescriptor);

    // Find out which WAYF to use for this Guard
    String wayfForGuard = null;
    String defaultWAYFLocation = null;
    for (String guardId : wayfs.keySet()) {
      if (guardId.equals(DEFAULT_WAYF_MARKER)) {
        defaultWAYFLocation = wayfs.get(guardId);
      }
      if (guardId.equals(guardID)) {
        wayfForGuard = wayfs.get(guardId);
      }
    }

    // Guard either gets its own WAYF or the default one for all other Guards
    mAndV.getModel().put("wayfLocation", (wayfForGuard != null) ? wayfForGuard : defaultWAYFLocation);

    log.info("Guard '" + guardID + "' successfully obtained WAYF location : " + ((wayfForGuard != null) ? wayfForGuard : defaultWAYFLocation));

    return mAndV;
  }

  /**
   * Adds an attribute to the ServletContext
   *
   * @param attrName attribute name
   * @param attrValue attribute value
   */
  private void setAttribute(String attrName, Object attrValue) {
    getServletContext().setAttribute(attrName, attrValue);
  }

  /**
   * Retrieves an attribute from the ServletContext
   *
   * @param attrName attribute name
   * @return String representing the attribute value
   */
  private String getAttribute(String attrName) {
    return (String)getServletContext().getAttribute(attrName);
  }

  // Setters
  public void setLoggerConfig(Log4JLoggerConfig loggerConfig) { this.loggerConfig = loggerConfig; }
  public void setLogger(Log4JLogger logger) { this.logger = logger; }
  public void setWayfs(HashMap<String, String> wayfs) { this.wayfs = wayfs; }
  public void setViewJSP(String viewJSP) { this.viewJSP = viewJSP; }

  // Getters
  public Log4JLoggerConfig getLoggerConfig() { return loggerConfig; }
  public Log4JLogger getLogger() { return logger; }
  public HashMap<String, String> getWayfs() { return wayfs; }
  public String getViewJSP() { return viewJSP; }
}
