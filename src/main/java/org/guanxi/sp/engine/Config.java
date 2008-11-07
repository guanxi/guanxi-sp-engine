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
  private String metadataCacheFile = null;

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

  public String getMetadataCacheFile() {
    return metadataCacheFile;
  }

  public void setMetadataCacheFile(String metadataCacheFile) {
    this.metadataCacheFile = metadataCacheFile;
  }
}
