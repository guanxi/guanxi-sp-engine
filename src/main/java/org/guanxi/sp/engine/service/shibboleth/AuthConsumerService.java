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

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.definitions.Shibboleth;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.IdPMetadata;
import org.guanxi.sp.Util;
import org.guanxi.sp.engine.Config;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_1_0.protocol.ResponseType;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.springframework.context.MessageSource;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

/**
 * Shibboleth AuthenticationStatement consumer service. This service accepts an AuthenticationStatement
 * from a Shibboleth Identity Provider and requests attributes for the subject. It then passes those
 * attributes to the appropriate Guard that started the session that resulted in the
 * AuthenticationStatement being sent here.
 * By the time this service reached, the Identity Provider will have been verified.
 *
 * @author Alistair Young alistair@codebrane.com
 * @author Marcin Mielnicki mielniczu@o2.pl - bug fixing
 */
public class AuthConsumerService extends MultiActionController implements ServletContextAware {
  private static final Logger logger = Logger.getLogger(AuthConsumerService.class.getName());

  /** The view to redirect to if no error occur */
  private String podderView = null;
  /** The view to use to display any errors */
  private String errorView = null;
  /** The variable to use in the error view to display the error */
  private String errorViewDisplayVar = null;
  /**
   * The variable to use in the error view to display a simple version
   * of the error explaining the likely cause.
   */
  private String errorViewSimpleVar;
  /**
   * This is the map of the processing thread associated with each session.
   */
  private static Map<HttpSession, AuthConsumerServiceThread> threads;
  /** The localised messages to use */
  private MessageSource messages = null;

  /**
   * This initialises the threads map which will be used to hold the AA conversation
   * threads by session.
   */
  public void init() {
	  threads = new TreeMap<HttpSession, AuthConsumerServiceThread>(new Comparator<HttpSession>(){
	    public int compare(HttpSession one, HttpSession two) {
	      return one.getId().compareTo(two.getId());
	    }
	  });
  } //init

  /**
   * Cleans up when the system shuts down
   */
  public void destroy() {
  } // destroy

  /**
   * This is the handler for the initial /shibb/acs page. This receives the
   * browser after it has visited the IdP and it spawns a thread associated
   * with the collection of attributes. It then redirects the user to the
   * process page which checks the status of the thread and displays a please
   * wait message, or forwards the user, as appropriate.
   *
   * @param request Servlet request
   * @param response Servlet response
   * @throws IOException if an error occurs
   * @throws GuanxiException if an error occurs
   * @throws KeyStoreException if an error occurs
   * @throws NoSuchAlgorithmException if an error occurs
   * @throws CertificateException if an error occurs
   */
  public void acs(HttpServletRequest request, HttpServletResponse response) throws IOException, GuanxiException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
    /* When a Guard initially set up a session with the Engine, it passed its session ID to
    * the Engine's WAYF Location web service. The Guard then passed the session ID to the
    * WAYF/IdP via the target parameter. So now it should come back here and we can
    * identify the Guard that we're working on behalf of.
    */
    String guardSession = request.getParameter(Shibboleth.TARGET_FORM_PARAM);

    Config config = (Config)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);

    /* When the Engine received the Guard's session, it munged it to an Engine session and
     * associated the Guard session ID with the Guard's ID. So now dereference the Guard's
     * session ID to get its ID and load it's metadata
     */
    EntityDescriptorType guardEntityDescriptor = (EntityDescriptorType)getServletContext().getAttribute(guardSession.replaceAll("GUARD", "ENGINE"));
    GuardRoleDescriptorExtensions guardNativeMetadata = Util.getGuardNativeMetadata(guardEntityDescriptor);

    IdPMetadata idpMetadata = (IdPMetadata)request.getAttribute(Config.REQUEST_ATTRIBUTE_IDP_METADATA);
    EntityFarm farm = (EntityFarm)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
    EntityManager manager = farm.getEntityManagerForID(idpMetadata.getEntityID());

    AuthConsumerServiceThread thread = null;
    thread = new AuthConsumerServiceThread(this, guardSession,
                                           guardNativeMetadata.getAttributeConsumerServiceURL(),
                                           idpMetadata.getAttributeAuthorityURL(),
                                           getPodderURL(guardSession, config, guardNativeMetadata),
                                           getGuardEntrityId(guardEntityDescriptor),
                                           guardNativeMetadata.getKeystore(), guardNativeMetadata.getKeystorePassword(),
                                           config.getTrustStore(), config.getTrustStorePassword(),
                                           (String)request.getAttribute(Config.REQUEST_ATTRIBUTE_IDP_PROVIDER_ID),
                                           (String)request.getAttribute(Config.REQUEST_ATTRIBUTE_IDP_NAME_IDENTIFIER),
                                           (ResponseType)request.getAttribute(Config.REQUEST_ATTRIBUTE_SAML_RESPONSE),
                                           messages, request, manager);
    new Thread(thread).start();
    threads.put(request.getSession(true), thread);

    response.sendRedirect("process");
  }
  
  /**
   * Opportunity for extending classes to determine the guardID
   * 
   * @param guardEntityDescriptor
   * @return
   */
  protected String getGuardEntrityId(EntityDescriptorType guardEntityDescriptor) throws GuanxiException
  {
	  return guardEntityDescriptor.getEntityID();
  }

  /**
   * Opportunity for extending classes to do some work to generate the podder URL
   *
   * @param sessionID the current Engine session ID
   * @param config the Engine config
   * @return the Podder URL for the Guard identified by sessionID
   * @throws GuanxiException if an error occurs
   */
  protected String getPodderURL(String sessionID, Config config, GuardRoleDescriptorExtensions guardNativeMetadata) throws GuanxiException {
	  return guardNativeMetadata.getPodderURL();
  }

  /**
   * This checks the status of the thread associated with this request. This will display
   * either a please wait message (with progress bar) or will forward the user to the
   * Podder.
   *
   * @param request  the HttpServletRequest
   * @param response the HttpServletResponse
   * @return the ModelAndView
   */
  @SuppressWarnings("unchecked")
  public ModelAndView process(HttpServletRequest request, HttpServletResponse response) {
    AuthConsumerServiceThread thread;
    HttpSession session;

    session = request.getSession(false);
    if ( session == null ) {
      ModelAndView mAndV;

      mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, "Your session has expired");

      return mAndV;
    }

    thread = threads.get(session);
    if ( thread == null ) {
      ModelAndView mAndV;

      mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, "Processing thread cannot be found");

      return mAndV;
    }
    if ( thread.isCompleted() ) {
      threads.remove(session); // TODO: Periodic unloading of expired threads?
    }
    return thread.getStatus();
  }

  /**
   * This is the name of the podder jsp page. This will be used
   * to set the Guard cookie.
   *
   * @return the podderView
   */
  public String getPodderView() {
    return podderView;
  }
  /**
   * This is the name of the podder jsp page. This will be used
   * to set the Guard cookie.
   *
   * @param podderView the podderView to set
   */
  public void setPodderView(String podderView) {
    this.podderView = podderView;
  }
  /**
   * This is the name of the error jsp page. This will be used
   * to display any issues that arise during the AA process.
   *
   * @return the errorView
   */
  public String getErrorView() {
    return errorView;
  }
  /**
   * This is the name of the error jsp page. This will be used
   * to display any issues that arise during the AA process.
   *
   * @param errorView the errorView to set
   */
  public void setErrorView(String errorView) {
    this.errorView = errorView;
  }
  /**
   * This is the key that is used to store the exception stack
   * trace and display it on the error page.
   *
   * @return the errorViewDisplayVar
   */
  public String getErrorViewDisplayVar() {
	  return errorViewDisplayVar;
  }
  /**
   * This is the key that is used to store the exception stack
   * trace and display it on the error page.
   *
   * @param errorViewDisplayVar the errorViewDisplayVar to set
   */
  public void setErrorViewDisplayVar(String errorViewDisplayVar) {
    this.errorViewDisplayVar = errorViewDisplayVar;
  }
  /**
   * This is the key that is used to store the more understandable
   * error message intended to reduce the amount of support required.
   *
   * @return the errorViewSimpleVar
   */
  public String getErrorViewSimpleVar() {
	  return errorViewSimpleVar;
  }
  /**
   * This is the key that is used to store the brief description
   * of the error and display it on the error page.
   *
   * @param errorViewSimpleVar the errorViewSimpleVar to set
   */
  public void setErrorViewSimpleVar(String errorViewSimpleVar) {
	  this.errorViewSimpleVar = errorViewSimpleVar;
  }

  public void setMessages(MessageSource messages) { this.messages = messages; }
}
