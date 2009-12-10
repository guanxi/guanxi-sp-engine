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
import org.springframework.web.context.ServletContextAware;
import org.springframework.context.MessageSource;
import org.apache.log4j.Logger;
import org.guanxi.common.GuanxiException;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class WebBrowserSSOAuthConsumerService extends MultiActionController implements ServletContextAware {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(WebBrowserSSOAuthConsumerService.class.getName());
  /** The localised messages to use */
  private MessageSource messages = null;
  /** The view to redirect to if no error occur */
  private String podderView = null;
  /** The view to use to display any errors */
  private String errorView = null;
  /** The variable to use in the error view to display the error */
  private String errorViewDisplayVar = null;

  public void init() {}

  public void destroy() {}

  /**
   * This is the handler for the initial /s2/wbsso/acs page. This receives the
   * browser after it has visited the IdP.
   *
   * @param request ServletRequest
   * @param response ServletResponse
   * @throws java.io.IOException
   * @throws org.guanxi.common.GuanxiException
   * @throws java.security.KeyStoreException
   * @throws java.security.NoSuchAlgorithmException
   * @throws java.security.cert.CertificateException
   */
  public void acs(HttpServletRequest request, HttpServletResponse response) throws IOException, GuanxiException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    String guardSession = request.getParameter("RelayState");
    String b64SAMLResponse = request.getParameter("SAMLResponse");

    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardSession.replaceAll("GUARD", "ENGINE"));
  }

  // Setters
  public void setMessages(MessageSource messages) { this.messages = messages; }
  public void setPodderView(String podderView) { this.podderView = podderView; }
  public void setErrorView(String errorView) { this.errorView = errorView; }
  public void setErrorViewDisplayVar(String errorViewDisplayVar) { this.errorViewDisplayVar = errorViewDisplayVar; }
}
