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
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class EmbeddedDiscoveryService extends MultiActionController implements ServletContextAware {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(EmbeddedDiscoveryService.class.getName());

  public void init() {}
  public void destroy() {}

  /**
   * This is the handler for the initial /s2/eds page
   *
   * @param request ServletRequest
   * @param response ServletResponse
   * @throws java.io.IOException if an error occurs
   */
  public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response)
              throws ServletException, IOException {
    ModelAndView mAndV = new ModelAndView();
    mAndV.setViewName("/saml2/eds");
    mAndV.getModel().put("testvar", "testvar-value");
    return mAndV;
  }
}
