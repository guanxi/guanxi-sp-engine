/**
 * 
 */
package org.guanxi.sp.engine.job.hibernate;

/**
 * This is the object that corresponds to an IdPMetadata entry in the
 * database. This is not an implementation of 
 * {@link org.guanxi.common.metadata.IdPMetadata}
 * because the certificate is stored in PEM encoded format.
 * 
 * @author matthew
 */
public class IdPMetadataDAO {  
  /**
   * This is the Attribute Authority URL for this IdP.
   */
  private String attributeAuthorityURL;
  /**
   * This is the entityID for this IdP.
   */
  private String entityID;
  /**
   * This is the PEM Certificate for this IdP. This should match
   * the x509 encoded certificate. This is used when the certificate
   * is written to the database, and the x509 certificate is used
   * when validation is required.
   */
  private String pemCertificate;
  
  /**
   * No argument constructor for Hibernate
   */
  public IdPMetadataDAO() {}
  
  /**
   * This gets the Attribute Authority URL. Where possible this should get the
   * AAURL that has the urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding
   * binding.
   * 
   * @return This returns the Attribute Authority URL which can be used for
   *         Attribute transfer with the IdP.
   */
  public String getAttributeAuthorityURL() {
    return attributeAuthorityURL;
  }
  
  /**
   * This sets the Attribute Authority URL. This Attribute Authority URL is expected
   * to be the Attribute Authority which corresponds to the 
   * urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding binding.
   * 
   * @param attributeAuthorityURL
   */
  public void setAttributeAuthorityURL(String attributeAuthorityURL) {
    this.attributeAuthorityURL = attributeAuthorityURL;
  }

  /**
   * This will return the entityID of the IdP.
   * 
   * @return The string representation of the IdP entityID.
   */
  public String getEntityID() {
    return entityID;
  }
  
  /**
   * This sets the entityID of the IdP.
   * 
   * @param entityID
   */
  public void setEntityID(String entityID) {
    this.entityID = entityID;
  }
  
  /**
   * This gets the PEM encoded version of the certificate used by the IdP.
   * 
   * @return This returns the PEM encoded representation of the Signing
   *         Certificate for the IdP.
   */
  public String getPemCertificate() {
    return pemCertificate;
  }
  
  /**
   * This sets the PEM encoded version of the certificate used by the IdP.
   * 
   * @param pemCertificate            The PEM encoded certificate to set.
   */
  public void setPemCertificate(String pemCertificate) {
    this.pemCertificate  = pemCertificate;
  }
}
