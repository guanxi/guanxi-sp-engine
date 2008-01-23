/* CVS Header
   $
   $
*/

package org.guanxi.sp.engine.form;

import org.springframework.validation.Validator;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;

public class RegisterIdPFormValidator implements Validator {
  public boolean supports(Class clazz) {
    return clazz.equals(RegisterIdP.class);
  }

  public void validate(Object obj, Errors errors) {
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "filename", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "entityID", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "aa", "error.field.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "x509", "error.field.required");
  }
}
