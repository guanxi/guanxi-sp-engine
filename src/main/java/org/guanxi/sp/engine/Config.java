/* CVS Header
   $Id$
   $Log$
   Revision 1.1.1.1  2008/01/23 15:30:55  alistairskye
   Standalone Engine module

*/

package org.guanxi.sp.engine;

import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;

public class Config implements ServletContextAware {
  /** The request attribute that holds the SAML response coming from an IdP.
   *  This is the XML that contains the IdP's AuthenticationStatement, afer a
   *  Guard has obtained the WAYF location and the user has authenticated at the IdP
   */
  public static final String REQUEST_ATTRIBUTE_SAML_RESPONSE = "REQUEST_ATTRIBUTE_SAML_RESPONSE";
  /** The request attribute that holds the IdP's providerId */
  public static final String REQUEST_ATTRIBUTE_IDP_PROVIDER_ID = "REQUEST_ATTRIBUTE_IDP_PROVIDER_ID";
  /** The request attribute that holds the IdP's name identifier */
  public static final String REQUEST_ATTRIBUTE_IDP_NAME_IDENTIFIER = "REQUEST_ATTRIBUTE_IDP_NAME_IDENTIFIER";
  /** The request attribute that holds the IdP's metadata */
  public static final String REQUEST_ATTRIBUTE_IDP_METADATA = "REQUEST_ATTRIBUTE_IDP_METADATA";

  private ServletContext servletContext = null;
  private String id = null;
  private String nameQualifier = null;
  private String keystore = null;
  private String keystorePassword = null;
  private String certificateAlias = null;
  private String keyType = null;
  private String trustStore = null;
  private String trustStorePassword = null;
  private String guardsMetadataDirectory = null;
  private String idPMetadataDirectory = null;

  public void init() {
    keystore = servletContext.getRealPath(keystore);
    trustStore = servletContext.getRealPath(trustStore);
    guardsMetadataDirectory = servletContext.getRealPath(guardsMetadataDirectory);
    idPMetadataDirectory = servletContext.getRealPath(idPMetadataDirectory);
  }

  public ServletContext getServletContext() {
    return servletContext;
  }

  public void setServletContext(ServletContext servletContext) {
    this.servletContext = servletContext;
  }
  
  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getNameQualifier() {
    return nameQualifier;
  }

  public void setNameQualifier(String nameQualifier) {
    this.nameQualifier = nameQualifier;
  }

  public String getKeystore() {
    return keystore;
  }

  public void setKeystore(String keystore) {
    this.keystore = keystore;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

  public String getCertificateAlias() {
    return certificateAlias;
  }

  public void setCertificateAlias(String certificateAlias) {
    this.certificateAlias = certificateAlias;
  }

  public String getKeyType() {
    return keyType;
  }

  public void setKeyType(String keyType) {
    this.keyType = keyType;
  }

  public String getTrustStore() {
    return trustStore;
  }

  public void setTrustStore(String trustStore) {
    this.trustStore = trustStore;
  }

  public String getTrustStorePassword() {
    return trustStorePassword;
  }

  public void setTrustStorePassword(String trustStorePassword) {
    this.trustStorePassword = trustStorePassword;
  }

  public String getGuardsMetadataDirectory() {
    return guardsMetadataDirectory;
  }

  public void setGuardsMetadataDirectory(String guardsMetadataDirectory) {
    this.guardsMetadataDirectory = guardsMetadataDirectory;
  }

  public String getIdPMetadataDirectory() {
    return idPMetadataDirectory;
  }

  public void setIdPMetadataDirectory(String idPMetadataDirectory) {
    this.idPMetadataDirectory = idPMetadataDirectory;
  }
}
