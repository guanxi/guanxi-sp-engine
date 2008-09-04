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
import org.guanxi.xal.w3.xmldsig.X509DataType;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.sp.engine.Config;
import org.guanxi.sp.engine.X509Chain;
import org.apache.xmlbeans.XmlOptions;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

public class RegisterIdPFormController extends SimpleFormController {
  /**
   * This is the configuration for this form
   */
  private Config config = null;
  /**
   * This is the example IdP document which is updated with the correct values
   * for the IdP currently being registered. This is then committed to disk and
   * loaded again to produce a second separate document.
   */
  private EntityDescriptorDocument exampleIdPDoc = null;
  /**
   * The localised messages
   */
  private MessageSource messageSource = null;

  public void setMessageSource(MessageSource messageSource) {
    this.messageSource = messageSource;
  }

  public void init() throws ServletException {
    try {
      config = (Config) getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);

      String exampleIdPFile = config.getIdPMetadataDirectory() + File.separator + "ExampleIDP.xml";

      exampleIdPDoc = EntityDescriptorDocument.Factory.parse(new File(exampleIdPFile));
    }
    catch (Exception ge) {
      throw new ServletException(ge);
    }
  }

  protected Object formBackingObject(HttpServletRequest request) throws ServletException {
    return new RegisterIdP();
  }

  @SuppressWarnings("unchecked")
  public ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response,
                               Object command, BindException errors) throws Exception {
    File newIdPFile = new File(config.getIdPMetadataDirectory(), request.getParameter("filename") + ".xml");
    createIdPFile(newIdPFile, request.getParameter("entityID"), request.getParameter("aa"), 
                  request.getParameter("x509").replaceAll("\r", ""));

    EntityDescriptorDocument loadedIdPDocument = EntityDescriptorDocument.Factory.parse(newIdPFile);

    EntityFarm farm = (EntityFarm)config.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_IDP_ENTITY_FARM);
    // The source is defined in config/spring/application/entity.xml
    EntityManager manager = farm.getEntityManagerForSource("local-metadata");
    Metadata metadataHandler = manager.createNewEntityHandler();
    metadataHandler.setPrivateData(loadedIdPDocument.getEntityDescriptor());
    manager.addMetadata(metadataHandler);

    X509Chain.loadX509CertsFromMetadata();

    ModelAndView mAndV = new ModelAndView();
    mAndV.setViewName(getSuccessView());
    mAndV.getModel().put("message",
        messageSource.getMessage("register.idp.success.message", null, request.getLocale()));
    return mAndV;
  }

  /**
   * This creates the initial IdP file that will be loaded on subsequent
   * restarts of the webapp.
   * 
   * @param file
   *          This is the file that will be created.
   * @param entityID
   *          This is the entityID of the IdP.
   * @param attributeAuthorityURL
   *          This is the URL of the Attribute Authority for the IdP.
   * @param signingCertificate
   *          This is the certificate used to sign the SAML assertions. It is
   *          base64 encoded. There should be no newlines or spaces in this.
   * @throws IOException
   *           This will be thrown if there is a problem writing to the file.
   */
  private void createIdPFile(File file, String entityID, String attributeAuthorityURL,
      String signingCertificate) throws IOException {
    X509DataType certificateObject;
    XmlOptions xmlOptions;

    exampleIdPDoc.getEntityDescriptor().setEntityID(entityID);
    exampleIdPDoc.getEntityDescriptor().getAttributeAuthorityDescriptorArray(0)
        .getAttributeServiceArray(0).setLocation(attributeAuthorityURL);
    certificateObject = exampleIdPDoc.getEntityDescriptor().getAttributeAuthorityDescriptorArray(0)
        .getKeyDescriptorArray(0).getKeyInfo().getX509DataArray(0);
    certificateObject.removeX509Certificate(0);
    certificateObject.addNewX509Certificate().setStringValue(signingCertificate);

    xmlOptions = new XmlOptions();
    xmlOptions.setSavePrettyPrint();
    xmlOptions.setSavePrettyPrintIndent(2);
    xmlOptions.setUseDefaultNamespace();
    xmlOptions.setCharacterEncoding("UTF-8");

    exampleIdPDoc.save(file);
  }
}
