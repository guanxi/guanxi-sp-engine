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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Utils;
import org.guanxi.common.definitions.SAML;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.sp.engine.service.generic.ProfileService;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.assertion.NameIDType;
import org.guanxi.xal.saml_2_0.metadata.EndpointType;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.protocol.AuthnRequestDocument;
import org.guanxi.xal.saml_2_0.protocol.AuthnRequestType;
import org.springframework.web.servlet.ModelAndView;

/**
 * SAML2 ProfileService implementation
 *
 * @author alistair
 */
public class SAML2ProfileService implements ProfileService {
  /** Our logger */
  protected static final Logger logger = Logger.getLogger(SAML2ProfileService.class.getName());
  /** The JSP to use to POST the AuthnRequest to the IdP */
  private String httpPOSTView = null;
  /** The JSP to use to GET the AuthnRequest to the IdP */
  private String httpRedirectView = null;
  /** The default endpoint for receiving SAML Response messages */
  private String assertionConsumerServiceURL = null;

  /** @see org.guanxi.sp.engine.service.generic.ProfileService#init() */
  public void init() {}

  /** @see org.guanxi.sp.engine.service.generic.ProfileService#doProfile(javax.servlet.http.HttpServletRequest, String, String, org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions, String, org.guanxi.common.entity.EntityFarm) */
  public ModelAndView doProfile(HttpServletRequest request, String guardID, String guardSessionID,
                                GuardRoleDescriptorExtensions guardNativeMetadata,
                                String entityID, EntityFarm farm) throws GuanxiException {
    ModelAndView mAndV = new ModelAndView();

    String relayState = guardSessionID.replaceAll("GUARD", "ENGINE");
    
    logger.debug("assertionConsumerServiceURL=" + assertionConsumerServiceURL);

    // Load the metadata for the IdP
    EntityManager manager = farm.getEntityManagerForID(entityID);
    if (manager == null) {
      logger.error("Could not find manager for IdP '" + entityID);
      throw new GuanxiException("Could not find manager for IdP " + entityID);
    }
    Metadata entityMetadata = manager.getMetadata(entityID);
    if (entityMetadata == null) {
      logger.error("Could not find manager for IdP " + entityID);
      throw new GuanxiException("Could not find metadata for IdP " + entityID);
    }
    EntityDescriptorType saml2Metadata = (EntityDescriptorType)entityMetadata.getPrivateData();

    String wbssoURL = null;
    String binding = null;
    EndpointType[] ssos = saml2Metadata.getIDPSSODescriptorArray(0).getSingleSignOnServiceArray();
    for (EndpointType sso : ssos) {
      if ((sso.getBinding().equalsIgnoreCase(SAML.SAML2_BINDING_HTTP_POST)) ||
          (sso.getBinding().equalsIgnoreCase(SAML.SAML2_BINDING_HTTP_REDIRECT))) {
        wbssoURL = sso.getLocation();
        if (sso.getBinding().equalsIgnoreCase(SAML.SAML2_BINDING_HTTP_POST)) binding = SAML.SAML2_BINDING_HTTP_POST;
        else if (sso.getBinding().equalsIgnoreCase(SAML.SAML2_BINDING_HTTP_REDIRECT)) binding = SAML.SAML2_BINDING_HTTP_REDIRECT;
        break;
      }
    }
    if (wbssoURL == null) {
      logger.error("IdP does not support WBSSO " + entityID);
      throw new GuanxiException("IdP does not support WBSSO " + entityID);
    }

    // Create an AuthnRequest
    AuthnRequestDocument authnRequestDoc = AuthnRequestDocument.Factory.newInstance();
    AuthnRequestType authnRequest = authnRequestDoc.addNewAuthnRequest();
    authnRequest.setID(Utils.createNCNameID());
    authnRequest.setVersion("2.0");
    authnRequest.setIssueInstant(Calendar.getInstance());
    Utils.zuluXmlObject(authnRequest, 0);
    NameIDType issuer = NameIDType.Factory.newInstance();
    issuer.setStringValue(guardID);
    authnRequest.setIssuer(issuer);
    authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
    authnRequest.setProtocolBinding(SAML.SAML2_BINDING_HTTP_POST);
    // Only if signed
    //authnRequest.setDestination("https://sgarbh.smo.uhi.ac.uk:8443/idp/profile/SAML2/POST/SSO");

    // Sort out the namespaces for saving the Response
    HashMap<String, String> namespaces = new HashMap<String, String>();
    namespaces.put(SAML.NS_SAML_20_PROTOCOL, SAML.NS_PREFIX_SAML_20_PROTOCOL);
    namespaces.put(SAML.NS_SAML_20_ASSERTION, SAML.NS_PREFIX_SAML_20_ASSERTION);

    // Do the profile quickstep
    String authnRequestForIdP = null;
    if (binding.equals(SAML.SAML2_BINDING_HTTP_REDIRECT)) {
      mAndV.setViewName(httpRedirectView);
      authnRequestForIdP = Utils.deflateBase64(authnRequestDoc.toString(), Utils.RFC1951_DEFAULT_COMPRESSION_LEVEL, Utils.RFC1951_NO_WRAP);
      try {
        authnRequestForIdP = URLEncoder.encode(authnRequestForIdP, "UTF-8");
        relayState = URLEncoder.encode(relayState, "UTF-8");
      }
      catch(UnsupportedEncodingException uee) {
        logger.error("couldn't encode SAMLRequest");
        throw new GuanxiException("couldn't encode SAMLRequest: " + uee.getMessage());
      }
    }
    else if (binding.equals(SAML.SAML2_BINDING_HTTP_POST)) {
      mAndV.setViewName(httpPOSTView);
      authnRequestForIdP = Utils.base64(authnRequestDoc.toString().getBytes());
    }

    // Send the AuthnRequest to the IdP
    mAndV.getModel().put("SAMLRequest", authnRequestForIdP);
    mAndV.getModel().put("RelayState", relayState);
    mAndV.getModel().put("wbsso_endpoint", wbssoURL);
    return mAndV;
  }

  // Setters
  public void setHttpPOSTView(String httpPOSTView) { this.httpPOSTView = httpPOSTView; }
  public void setHttpRedirectView(String httpRedirectView) { this.httpRedirectView = httpRedirectView; }
  public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) { this.assertionConsumerServiceURL = assertionConsumerServiceURL; }
}
