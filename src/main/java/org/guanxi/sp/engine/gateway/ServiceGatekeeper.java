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

package org.guanxi.sp.engine.gateway;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ServiceGatekeeper extends HandlerInterceptorAdapter implements ServletContextAware {
  /** If set to true, attribute rules are not processed and the application is open to all */
  private boolean debug = false;
  /** The ServletContext, passed to us by Spring as we are ServletContextAware */
  @SuppressWarnings("unused")
  private ServletContext servletContext = null;

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
    // If the debug property is set, just let the request through.
    if (debug) return true;
    
    return true;
  }

  // Called by Spring as we are ServletContextAware
  public void setServletContext(ServletContext servletContext) { this.servletContext = servletContext; }

  // Setters
  public void setDebug(boolean debug) { this.debug = debug; }

  // Getters
  public boolean getDebug() { return debug; }
}
