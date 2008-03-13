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
