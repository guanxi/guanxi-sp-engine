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

/**
 * Backing object for the Register IdP form
 */
public class RegisterIdP {
  private String filename = null;
  private String entityID = null;
  private String aa = null;
  private String x509 = null;
  
  public String getFilename() {
    return filename;
  }

  public String getEntityID() {
    return entityID;
  }

  public String getAa() {
    return aa;
  }

  public String getX509() {
    return x509;
  }

  public void setFilename(String filename) {
    this.filename = filename;
  }

  public void setEntityID(String entityID) {
    this.entityID = entityID;
  }

  public void setAa(String aa) {
    this.aa = aa;
  }

  public void setX509(String x509) {
    this.x509 = x509;
  }
}
