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

import org.springframework.validation.Validator;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.web.context.ServletContextAware;
import org.guanxi.sp.engine.Config;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.Utils;

import javax.servlet.ServletContext;
import java.io.File;

public class RegisterGuardFormValidator implements Validator, ServletContextAware {
  /** The servlet context */
  private ServletContext servletContext = null;

  /**
   * Sets the servlet context
   * @param servletContext The servlet context
   */
  public void setServletContext(ServletContext servletContext) {
    this.servletContext = servletContext;
  }
  
  public boolean supports(Class clazz) {
    return clazz.equals(RegisterGuard.class);
  }
  
  public void validate(Object obj, Errors errors) {
    RegisterGuard form = (RegisterGuard)obj;

    if (checkForDuplicateGuard(form.getGuardid())) {
      errors.rejectValue("guardid", "register.guard.error.duplicate.guardid");
    }

    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "guardid", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "scheme", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "port", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "url", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "applicationName", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "orgunit", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "org", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "city", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "locality", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "contactCompany", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "contactGivenName", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "contactSurname", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "contactEmail", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "contactPhone", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "country", "error.field.required");
  }

  private boolean checkForDuplicateGuard(String guardid) {
    Config config = (Config)servletContext.getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);
    String metadataDirectory = config.getGuardsMetadataDirectory() + Utils.SLASH + guardid.toLowerCase();
    File ksFile = new File(metadataDirectory + Utils.SLASH + guardid.toLowerCase() + ".jks");
    return ksFile.exists();
  }
}
