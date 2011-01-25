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

import org.apache.log4j.Logger;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.sp.engine.service.generic.ProfileService;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class DiscoveryProfileService implements ProfileService {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(DiscoveryProfileService.class.getName());

  /** The name of the view to use to redirect to the EDS */
  private String viewName = null;
  /** Where the EDS is */
  private String edsBaseURL = null;

  /** @see org.guanxi.sp.engine.service.generic.ProfileService#init() */
  public void init() {}

  /** @see org.guanxi.sp.engine.service.generic.ProfileService#doProfile(javax.servlet.http.HttpServletRequest, String, String, org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions, String, org.guanxi.common.entity.EntityFarm) */
  public ModelAndView doProfile(HttpServletRequest request, String guardID, String guardSessionID,
                                GuardRoleDescriptorExtensions guardNativeMetadata,
                                String entityID, EntityFarm farm) throws GuanxiException {
    ModelAndView mAndV = new ModelAndView();
    mAndV.setViewName(viewName);
    
    try {
      String edsURL = edsBaseURL + "?entityID=" + URLEncoder.encode(guardID, "UTF-8");
      edsURL += "&return=" + URLEncoder.encode(request.getRequestURL() + "?" + Guanxi.WAYF_PARAM_GUARD_ID + "=" + guardID +
                                               "&" + Guanxi.WAYF_PARAM_SESSION_ID + "=" + guardSessionID, "UTF-8");
      edsURL += "&returnIDParam=" + URLEncoder.encode("edsEntityID", "UTF-8");

      mAndV.getModel().put("edsURL", edsURL);
    }
    catch(UnsupportedEncodingException use) {
      logger.error("Could not encode EDS URL", use);
      mAndV.getModel().put("edsError", use.getMessage());
    }

    return mAndV;
  }

  // Setters
  public void setViewName(String viewName) { this.viewName = viewName; }
  public void setEdsBaseURL(String edsBaseURL) { this.edsBaseURL = edsBaseURL; }
}
