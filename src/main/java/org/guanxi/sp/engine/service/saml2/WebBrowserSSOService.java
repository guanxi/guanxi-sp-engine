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
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.context.ServletContextAware;
import org.springframework.context.MessageSource;
import org.apache.log4j.Logger;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WebBrowserSSOService extends MultiActionController implements ServletContextAware {
  private static final Logger logger = Logger.getLogger(WebBrowserSSOService.class.getName());

  /** The localised messages to use */
  private MessageSource messages = null;

  public void init() {}

  public ModelAndView wbsso(HttpServletRequest request, HttpServletResponse response) {
    String entityID = request.getParameter("entityID");

    EntityFarm farm = (EntityFarm)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
    EntityManager manager = farm.getEntityManagerForID(entityID);
    Metadata entityMetadata = manager.getMetadata(entityID);
    EntityDescriptorType saml2Metadata = (EntityDescriptorType)entityMetadata.getPrivateData();
    logger.info(saml2Metadata.getEntityID());

    return null;
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
}
