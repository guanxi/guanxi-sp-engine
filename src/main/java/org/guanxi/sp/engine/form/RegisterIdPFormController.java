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

package org.guanxi.sp.engine.form;

import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.BindException;
import org.springframework.context.MessageSource;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EndpointType;
import org.guanxi.xal.saml_2_0.metadata.KeyDescriptorType;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.Utils;
import org.guanxi.sp.engine.X509Chain;
import org.guanxi.sp.engine.Config;
import org.apache.xmlbeans.XmlOptions;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;

public class RegisterIdPFormController extends SimpleFormController {
  private Config config = null;
  private EntityDescriptorDocument exampleIdpDoc = null;
  /** The localised messages */
  private MessageSource messageSource = null;

  public void setMessageSource(MessageSource messageSource) {
    this.messageSource = messageSource;
  }

  public void init() throws ServletException {
    try {
      config = (Config)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);

      String exampleIdPFile = config.getIdPMetadataDirectory() + Utils.SLASH + "ExampleIDP.xml";

      exampleIdpDoc = EntityDescriptorDocument.Factory.parse(new File(exampleIdPFile));
    }
    catch(Exception ge) {
      throw new ServletException(ge);
    }
  }

  protected Object formBackingObject(HttpServletRequest request) throws ServletException {
    return new RegisterIdP();
  }

  public ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response,
                               Object command, BindException errors) throws Exception {
    exampleIdpDoc.getEntityDescriptor().setEntityID(request.getParameter("entityID"));

    EndpointType aa = exampleIdpDoc.getEntityDescriptor().getAttributeAuthorityDescriptorArray(0).getAttributeServiceArray(0);
    aa.setLocation(request.getParameter("aa"));

    KeyDescriptorType keyDesc = exampleIdpDoc.getEntityDescriptor().getAttributeAuthorityDescriptorArray(0).getKeyDescriptorArray(0);
    keyDesc.getKeyInfo().getX509DataArray(0).removeX509Certificate(0);
    keyDesc.getKeyInfo().getX509DataArray(0).addNewX509Certificate().setStringValue(request.getParameter("x509").replaceAll("\r", ""));

    XmlOptions xmlOptions = new XmlOptions();
    xmlOptions.setSavePrettyPrint();
    xmlOptions.setSavePrettyPrintIndent(2);
    xmlOptions.setUseDefaultNamespace();
    xmlOptions.setCharacterEncoding("UTF-8");

    String newIdPFile = config.getIdPMetadataDirectory() + Utils.SLASH + request.getParameter("filename") + ".xml";
    exampleIdpDoc.save(new File(newIdPFile), xmlOptions);

    EntityDescriptorDocument edDoc = EntityDescriptorDocument.Factory.parse(new File(newIdPFile));
    getServletContext().setAttribute(request.getParameter("entityID"), edDoc.getEntityDescriptor());

    X509Chain.loadX509CertsFromMetadata();

    ModelAndView mAndV = new ModelAndView();
    mAndV.setViewName(getSuccessView());
    mAndV.getModel().put("message", messageSource.getMessage("register.idp.success.message",
                                                             null, request.getLocale()));
    return mAndV;
  }
}
