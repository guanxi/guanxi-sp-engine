/* CVS Header
   $
   $
*/

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
