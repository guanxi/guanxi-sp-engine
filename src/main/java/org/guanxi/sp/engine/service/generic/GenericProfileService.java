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

package org.guanxi.sp.engine.service.generic;

import org.apache.log4j.Logger;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.definitions.SAML;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.sp.Util;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.metadata.EndpointType;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.springframework.context.MessageSource;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * Generic profile service for selecting a profile based on metadata
 *
 * @author alistair
 */
public class GenericProfileService extends MultiActionController implements ServletContextAware {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(GenericProfileService.class.getName());
  /** The marker in our entityID map for the one to use as the default entityID */
  private static final String DEFAULT_ENTITYID_MARKER = "__DEFAULT__";
  /** The localised messages to use */
  private MessageSource messages = null;
  /** The JSP to use to display any errors */
  private String errorView = null;
  /** The request attribute that holds the error message for the error view */
  private String errorViewDisplayVar = null;
  /** The Shibboleth profile service to use */
  private ProfileService shibbolethProfileService = null;
  /** The SAML2 profile service to use */
  private ProfileService saml2ProfileService = null;
  /** The list of Guard to entityID mappings */
  private HashMap<String, String> entityIDs = null;

  public void init() {}

  public ModelAndView gps(HttpServletRequest request, HttpServletResponse response) {
    String guardID = request.getParameter(Guanxi.WAYF_PARAM_GUARD_ID);
    String guardSessionID = request.getParameter(Guanxi.WAYF_PARAM_SESSION_ID);
    
    // Optional entityID
    String entityID = request.getParameter("entityID");

    // If the Guard hasn't specified an entityID, see if it has one registered for it
    if (entityID == null) {
      if (entityIDs != null) {
        String entityIDForGuard = null;
        String defaultEntityID = null;

        // Find out which entityID to use for this Guard
        for (String registeredGuardID : entityIDs.keySet()) {
          if (registeredGuardID.equals(DEFAULT_ENTITYID_MARKER)) {
            defaultEntityID = entityIDs.get(registeredGuardID);
          }
          if (guardID.equals(registeredGuardID)) {
            entityIDForGuard = entityIDs.get(registeredGuardID);
          }
        }

        entityID = (entityIDForGuard != null) ? entityIDForGuard : defaultEntityID;
        logger.info("Guard '" + guardID + "' obtained entityID : " + entityID);
      }
    }
    else {
      logger.info("Guard '" + guardID + "' specified entityID : " + entityID);
    }

    // Get the Guard's metadata, previously loaded by the Bootstrapper
    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardID);
    if (guardEntityDescriptor == null) {
      logger.error("Guard '" + guardID + "' not found in metadata repository");
      ModelAndView mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, messages.getMessage("engine.error.no.guard.metadata",
                                                                    null, request.getLocale()));
      return mAndV;
    }
    
    // Load the GuanxiGuardService node from the metadata
    GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);

    /* Convert the Guard's session ID to an Engine session ID and store the Guard's GuanxiGuardService
     * node under it.
     */
    getServletContext().setAttribute(guardSessionID.replaceAll("GUARD", "ENGINE"), guardEntityDescriptor);

    EntityFarm farm = (EntityFarm)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
    try {
      return getProfileService(farm, entityID).doProfile(guardID, guardSessionID, guardNativeMetadata, entityID, farm);
    }
    catch(GuanxiException ge) {
      logger.error("Shibboleth error: ", ge);
      ModelAndView mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, messages.getMessage("engine.error.no.guard.metadata",
                                                                    null, request.getLocale()));
      return mAndV;
    }
  }

  /**
   * Selects a profile to use
   *
   * @param farm entity farm
   * @param entityID entityID of the IdP or null if there isn't one
   * @return ProfileService instance which defaults to Shibboleth
   * @throws GuanxiException if an error occurs
   */
  private ProfileService getProfileService(EntityFarm farm, String entityID) throws GuanxiException {
    if (entityID == null) {
      // No entityID so assume Shibboleth
      return shibbolethProfileService;
    }
    else {
      // Load the metadata for the IdP
      EntityManager manager = farm.getEntityManagerForID(entityID);
      if (manager == null) {
        throw new GuanxiException("Could not find manager for IdP '" + entityID);
      }
      Metadata entityMetadata = manager.getMetadata(entityID);
      if (entityMetadata == null) {
        throw new GuanxiException("Could not find metadata for IdP " + entityID);
      }
      EntityDescriptorType saml2Metadata = (EntityDescriptorType)entityMetadata.getPrivateData();

      // Look for SAML2 endpoints
      EndpointType[] ssos = saml2Metadata.getIDPSSODescriptorArray(0).getSingleSignOnServiceArray();
      for (EndpointType sso : ssos) {
        String binding = sso.getBinding();
        if ((binding.equals(SAML.SAML2_BINDING_HTTP_POST)) ||
            (binding.equals(SAML.SAML2_BINDING_HTTP_REDIRECT))) {
          return saml2ProfileService;
        }
      }

      // If we get here, SAML2 isn't supported so use Shibboleth
      return shibbolethProfileService;
    }
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
  public void setErrorView(String errorView) { this.errorView = errorView; }
  public void setErrorViewDisplayVar(String errorViewDisplayVar) { this.errorViewDisplayVar = errorViewDisplayVar; }
  public void setShibbolethProfileService(ProfileService shibbolethProfileService) { this.shibbolethProfileService = shibbolethProfileService; }
  public void setSaml2ProfileService(ProfileService saml2ProfileService) { this.saml2ProfileService = saml2ProfileService; }
  public void setEntityIDs(HashMap<String, String> entityIDs) { this.entityIDs = entityIDs; }
}
