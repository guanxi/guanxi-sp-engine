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

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMWriter;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlOptions;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.filters.FileName;
import org.guanxi.common.filters.RFC2253;
import org.guanxi.xal.saml_2_0.metadata.*;
import org.guanxi.xal.saml2.metadata.GuanxiGuardServiceDocument;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.sp.engine.Config;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.xal.w3.xmldsig.X509DataType;
import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.BindException;
import org.springframework.context.MessageSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.util.*;

/**
 * CA is the Guanxi Service Provider Certification Authority. It's used to
 * generate public/private key pairs for Guards and to digitally sign
 * the corresponding certificate and place it in a keystore.
 * <p />
 * The keystores are stored for later use by the identity masquerading
 * layer to properly authenticate an HTTPS connection to an IdP on
 * behalf of a Guard.
 * <p />
 * The way it's used is a user will access a web form at the Engine and
 * supply required information. The Engine will respond with a visual
 * representation of the signed certificate chain and will also create
 * a new keystore with that chain in it.
 * <p />
 * The idea is that each Guard will have it's own directory in the
 * WEB-INF/metadata/guards directory. The name of the directory will be
 * the Guard's ID. In there we'll store the XML files the Engine needs
 * to work on behalf of the Guard as well as a ZIP file of the Guard's
 * configuration which the owner of the Guard can download.
 *
 * @author Alistair Young (alistair@smo.uhi.ac.uk)
 */
public class RegisterGuardFormController extends SimpleFormController {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(RegisterGuardFormController.class.getName());
  /** Our config object */
  private Config config = null;
  /** Contains the full path to the keystore to be used for signing CSRs */
  private String rootCAKeystore = null;
  /** Password for the signing keystore */
  private String rootCAKeystorePassword = null;
  /** The alias of the certificate entry in the signing keystore */
  private String rootCAKeystoreAlias = null;
  /** The localised messages */
  private MessageSource messageSource = null;
  /** The view to use to display any errors */
  private String errorView = null;
  /** The variable to use in the error view to display the error */
  private String errorViewDisplayVar = null;

  public void setMessageSource(MessageSource messageSource) {
    this.messageSource = messageSource;
  }

  public void setErrorView(String errorView) {
    this.errorView = errorView;
  }

  public void setErrorViewDisplayVar(String errorViewDisplayVar) {
    this.errorViewDisplayVar = errorViewDisplayVar;
  }

  /**
   * Initialises the CA by loading the BouncyCastle Security Provider
   *
   * @throws ServletException if an error occurs
   */
  public void init() throws ServletException {

    // Get the config
    config = (Config)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG);

    /* Where to load the root keystore. This contains the certificate and private key
     * of the Service Provider Engine and is used to sign Guard CSRs.
     */
    rootCAKeystore = config.getKeystore();
    // ... the password for opening the keystore ...
    rootCAKeystorePassword = config.getKeystorePassword();
    // ... the alias of the Engine's certificate in the keystore ...
    rootCAKeystoreAlias = config.getCertificateAlias();
  }

  /**
   * Cleans up the CA by unloading the BouncyCastle Service Provider
   */
  public void destroy() {
  }

  /**
   * Called once, just before the HTML form is displayed for the first time.
   * It's here that we initialise the ControlPanelForm to tell the form what
   * it can do with the job.
   *
   * @param request Standard HttpServletRequest
   * @return Instance of ControlPanelForm
   * @throws ServletException
   */
  protected Object formBackingObject(HttpServletRequest request) throws ServletException {
    return new RegisterGuard();
  }

  /**
   * Handles input from the web form to generate and sign a CSR and store the resulting
   * certificate chain in a keystore.
   *
   * @param request Standard issue HttpServletRequest
   * @param response Standard issue HttpServletResponse
   * @throws ServletException
   */
  @SuppressWarnings("unchecked")
  public ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response,
                               Object command, BindException errors) throws ServletException {

    RegisterGuard form = (RegisterGuard)command;
	String escapedGuardID = FileName.encode(form.getGuardid().toLowerCase());

    // Adjust the metadata directory for the new Guard
    String metadataDirectory = config.getGuardsMetadataDirectory() + File.separator + escapedGuardID;

    // Create the new Guard metadata directory
    if (!createGuardMetadataDirectory(metadataDirectory)) {
      ModelAndView mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, messageSource.getMessage("register.guard.error.create.dir",
                                                                         null, request.getLocale()));
      return mAndV;
    }

    // Build an X509 name
    String x509DN = "CN=" + RFC2253.encode(form.getGuardid());
    x509DN += ",OU=" + RFC2253.encode(form.getOrgunit());
    x509DN += ",O=" + RFC2253.encode(form.getOrg());
    x509DN += ",L=" + RFC2253.encode(form.getCity());
    x509DN += ",ST=" + RFC2253.encode(form.getLocality());
    x509DN += ",C=" + RFC2253.encode(form.getCountry());

    // Generate a CSR and sign it
    CABean caBean = createSignedCertificateChain(x509DN, config.getKeyType());

    // Use a random number for the keystore password
    Random randomNumberGenerator = new Random();
    String keystorePassword = String.valueOf(randomNumberGenerator.nextInt());

    /* Store the certificate chain in a keystore. The name of the keystore must
     * correspond to the ID of the Guard that will use it. i.e. when the Engine
     * masquerades for the Guard over the SSL connection to the IdP, it must
     * know where the Guard's keystore is.
     * To this end the keystore will be the lowercase equivalent of the Guard ID
     * and it's certificate alias will be the same.
     */
    String guardKeystore = metadataDirectory + File.separator + escapedGuardID + ".jks";
    createKeystoreWithChain(guardKeystore, form.getGuardid().toLowerCase(),
                            keystorePassword, caBean);

    createGuardMetadataFile(metadataDirectory, guardKeystore, keystorePassword, form, caBean);

    // Load the new Guard so the main Engine can use it
    loadGuardMetadata(metadataDirectory + File.separator + escapedGuardID + ".xml");

    // Show the certificate chain to the user
    displayChain(request, response, caBean);

    return new ModelAndView(getSuccessView(), errors.getModel());
  }

  /**
   * Creates an authenticated certificate chain for the specified X509 name
   *
   * @param x509DN X509 name to for which to create a certificate chain
   * @param keyType The type of the key, e.g. "RSA", "DSA"
   * @return Returns a CABean instance encapsulating certificate chain and key information
   * or null if an error occurred
   */
  private CABean createSignedCertificateChain(String x509DN, String keyType) {
    try {
      // Create a public/private keypair...
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyType);
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keypair = keyGen.generateKeyPair();
      PrivateKey clientPrivateKey = keypair.getPrivate();
      PublicKey clientPublicKey = keypair.getPublic();

      // ...and a CSR from them...
      PKCS10CertificationRequest csr = generateRequest(x509DN, clientPublicKey, clientPrivateKey, keyType);

      // ...sign it
      KeyStore rootKS = loadRootKeyStore();
      X509Certificate rootCert = (X509Certificate)rootKS.getCertificate(rootCAKeystoreAlias);
      if (rootCert == null) {
        logger.error("Can't get root certificate from CA keystore");
        return null;
      }
      PrivateKey rootPrivKey = (PrivateKey)rootKS.getKey(rootCAKeystoreAlias, rootCAKeystorePassword.toCharArray());
      X509Certificate[] signedChain = createSignedCert(rootCert, rootPrivKey, csr, keyType);

      //...package up the result...
      CABean caBean = new CABean();
      caBean.setChain(signedChain);
      caBean.setCSRPrivateKey(clientPrivateKey);
      caBean.setSubjectDN(x509DN);

      // ...and send it back
      return caBean;
    }
    catch(Exception e) {
      logger.error(e);
      return null;
    }
  }

  /**
   * Creates a JKS keystore and imports the specified certificate chain
   *
   * @param ksFileName The full path/name of the keystore to create
   * @param alias The alias for the certificate entry to create
   * @param password The password for the keystore and also the private key
   * @param caBean CABean instance from a call to createSignedCertificateChain
   */
  private void createKeystoreWithChain(String ksFileName,
                                       String alias, String password,
                                       CABean caBean) {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      ks.load(null, null);
      ks.setKeyEntry(alias, caBean.getCSRPrivateKey(), password.toCharArray(), caBean.getChain());
      ks.store(new FileOutputStream(ksFileName), password.toCharArray());
    }
    catch(Exception e) {
      logger.error(e);
    }
  }

  /**
   * Generates a Certificate Signing Request (CSR) for an entity
   *
   * @param x509DN The X509 name of the entity
   * @param pubkey The public key of the entity
   * @param privkey The private key of the entity
   * @param keyType The type of the key, e.g. "RSA", "DSA"
   * @return A PKCS10CertificationRequest or null if an error occurred
   */
  private PKCS10CertificationRequest generateRequest(String x509DN, PublicKey pubkey, PrivateKey privkey,
                                                     String keyType) {
    try {
      if (keyType.toLowerCase().equals("rsa")) {
        return new PKCS10CertificationRequest("SHA256withRSA",
                                              new X500Principal(x509DN),
                                              pubkey,
                                              null,
                                              privkey);
      }
      else if (keyType.toLowerCase().equals("dsa")) {
        return new PKCS10CertificationRequest("DSAWithSHA1",
                                              new X500Principal(x509DN),
                                              pubkey,
                                              null,
                                              privkey);
      }
      else {
        logger.error("Unrecognised key type : " + keyType);
        return null;
      }

    }
    catch(Exception e) {
      logger.error(e);
      return null;
    }
  }

  /**
   * Handles the nitty gritty of signing a CSR
   *
   * @param rootCert The certificate of the root authority who will vouch for the entity
   * @param rootPrivKey The private key of the root authority who will vouch for the entity
   * @param csr The entitie's CSR
   * @param keyType The type of the key, e.g. "RSA", "DSA"
   * @return A certificate chain as an array of X509Certificate instances or null if an
   * error occurred
   */
  private X509Certificate[] createSignedCert(X509Certificate rootCert, PrivateKey rootPrivKey,
                                             PKCS10CertificationRequest csr, String keyType) {
    X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

    try {
      Date validFrom = new Date();
      validFrom.setTime(validFrom.getTime() - (10 * 60 * 1000));
      Date validTo = new Date();
      validTo.setTime(validTo.getTime() + (20 * (24 * 60 * 60 * 1000)));

      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
      certGen.setIssuerDN(rootCert.getSubjectX500Principal());
      certGen.setNotBefore(validFrom);
      certGen.setNotAfter(validTo);
      certGen.setSubjectDN(csr.getCertificationRequestInfo().getSubject());
      certGen.setPublicKey(csr.getPublicKey("BC"));

      if (keyType.toLowerCase().equals("rsa"))
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
      if (keyType.toLowerCase().equals("dsa"))
        certGen.setSignatureAlgorithm("DSAWithSHA1");

      certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert));
      certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(csr.getPublicKey("BC")));
      certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
      certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

      X509Certificate  issuedCert = certGen.generate(rootPrivKey, "BC");
      return new X509Certificate[] { issuedCert, rootCert };
    }
    catch(Exception e) {
      logger.error(e);
      return null;
    }
  }

  /**
   * Loads the root authority's keystore containing it's private key and
   * public key certificate
   *
   * @return A KeyStore instance or null if an error occurred
   */
  private KeyStore loadRootKeyStore() {
    try {
      KeyStore ks = null;
      ks = KeyStore.getInstance("jks");

      FileInputStream fis = null;
      //fis = new FileInputStream(new File("/Users/alistair/dev/incubator/SSL/keys/guanxi.uhi.ac.uk.jks"));
      fis = new FileInputStream(rootCAKeystore);

      ks.load(fis, rootCAKeystorePassword.toCharArray());

      return ks;
    }
    catch(Exception e) {
      logger.error(e);
      return null;
    }
  }

  /**
   * Output a visual representation of a certificate chain
   *
   * @param request Standard issue HttpServletRequest
   * @param response Standard issue HttpServletResponse
   * @param caBean CABean instance from a call to createSignedCertificateChain
   */
  private void displayChain(HttpServletRequest request, HttpServletResponse response, CABean caBean) {
    try {
      PEMWriter pemWriter = new PEMWriter(response.getWriter());
      X509Certificate[] certs = caBean.getChain();
      for (int count=0; count < certs.length; count++) {
        pemWriter.writeObject(certs[count]);
      }
      pemWriter.close();
    }
    catch(Exception e) {
      logger.error(e);
      try {
        request.setAttribute("ERROR_ID", "ID_NEED_ALL_PARAMETERS");
        request.setAttribute("ERROR_MESSAGE", e.getMessage());
        request.getRequestDispatcher("/guanxi_sp/sp_error.jsp").forward(request, response);
      }
      catch(Exception ex) {
        logger.error(e);
      }
    }
  }

  /**
   * Creates the directory to hold a new Guard's metadata
   *
   * @param dir Full path of the directory to create
   * @return true on success, otherwise false
   */
  public boolean createGuardMetadataDirectory(String dir) {
    return new File(dir).mkdir();
  }

  /**
   * Creates a SAML2 metadata file for the Guard based on its settings in the form
   *
   * @param guardDir Where to create the metadata file
   * @param keystore The name of the Guard's keystore that has been created
   * @param keystorePassword The password for the Guard's keystore
   * @param form The form object describing the Guard
   * @param caBean The bean encapsulating certificate information
   */
  private void createGuardMetadataFile(String guardDir, String keystore, String keystorePassword,
                                       RegisterGuard form, CABean caBean) {
    EntityDescriptorDocument entityDoc = EntityDescriptorDocument.Factory.newInstance();
    EntityDescriptorType entityDescriptor = entityDoc.addNewEntityDescriptor();

    entityDescriptor.setEntityID(form.getGuardid().toLowerCase());

    // <EntityDescriptor>/<RoleDescriptor>
    RoleDescriptorDocument roleDoc = RoleDescriptorDocument.Factory.newInstance();
    RoleDescriptorType role = roleDoc.addNewRoleDescriptor();
    // <EntityDescriptor>/<RoleDescriptor>/<Extensions>/<GuanxiGuardService>
    GuanxiGuardServiceDocument guardService = GuanxiGuardServiceDocument.Factory.newInstance();
    GuardRoleDescriptorExtensions guardExt = guardService.addNewGuanxiGuardService();
    String appURL = form.getScheme() + "://" + form.getUrl();
    if (!form.getPort().equals("80"))
      appURL += ":" + form.getPort();
    appURL += "/" + form.getApplicationName();
    guardExt.setVerifierURL(appURL + "/guard.sessionVerifier");
    guardExt.setAttributeConsumerServiceURL(appURL + "/guard.guanxiGuardACS");
    guardExt.setPodderURL(appURL + "/guard.guanxiGuardPodder");
    guardExt.setKeystore(keystore);
    guardExt.setKeystorePassword(keystorePassword);
    ExtensionsType ext = ExtensionsType.Factory.newInstance();
    ext.getDomNode().appendChild(ext.getDomNode().getOwnerDocument().importNode(guardExt.getDomNode(), true));
    role.setExtensions(ext);

    // Add the GuanxiGuardDescriptor to the EntityDescriptor
    entityDescriptor.setRoleDescriptorArray(new RoleDescriptorType[] {role});

    // <EntityDescriptor>/<Organization>
    OrganizationType organisation = entityDescriptor.addNewOrganization();
    // <EntityDescriptor>/<Organization>/<OrganizationName>
    LocalizedNameType orgName = LocalizedNameType.Factory.newInstance();
    orgName.setLang("en");
    orgName.setStringValue(form.getOrg());
    organisation.setOrganizationDisplayNameArray(new LocalizedNameType[] {orgName});
    // <EntityDescriptor>/<Organization>/<OrganizationDisplayName>
    LocalizedNameType displayName = LocalizedNameType.Factory.newInstance();
    displayName.setLang("en");
    displayName.setStringValue(form.getOrg());
    organisation.setOrganizationNameArray(new LocalizedNameType[] {displayName});
    // <EntityDescriptor>/<Organization>/<OrganizationURL>
    LocalizedURIType orgURL = LocalizedURIType.Factory.newInstance();
    orgURL.setLang("en");
    orgURL.setStringValue(form.getOrg());
    organisation.setOrganizationURLArray(new LocalizedURIType[] {orgURL});

    // <EntityDescriptor>/<SPSSODescriptor>
    SPSSODescriptorType spSSO = entityDescriptor.addNewSPSSODescriptor();

    // <EntityDescriptor>/SPSSODescriptor>/<KeyDescriptor> : signing
    KeyDescriptorType keyDescriptor = spSSO.addNewKeyDescriptor();
    keyDescriptor.setUse(KeyTypes.SIGNING);
    KeyInfoType keyInfo = keyDescriptor.addNewKeyInfo();
    X509DataType x509Data = keyInfo.addNewX509Data();

    StringWriter sw = new StringWriter();
    PEMWriter pemWriter = new PEMWriter(sw);
    String x509 = null;

    try {
      pemWriter.writeObject(caBean.getSubjectCertificate());
      pemWriter.close();
      x509 = sw.toString();
      x509 = x509.replaceAll("-----BEGIN CERTIFICATE-----", "");
      x509 = x509.replaceAll("-----END CERTIFICATE-----", "");
      x509Data.addNewX509Certificate().setStringValue(x509);
    }
    catch(Exception e) {
      logger.error("Error creating Guard signing certificate metadata", e);
    }
    // <EntityDescriptor>/SPSSODescriptor>/<KeyDescriptor> : encryption
    keyDescriptor = spSSO.addNewKeyDescriptor();
    keyDescriptor.setUse(KeyTypes.ENCRYPTION);
    keyInfo = keyDescriptor.addNewKeyInfo();
    x509Data = keyInfo.addNewX509Data();
    try {
      x509Data.addNewX509Certificate().setStringValue(x509);
    }
    catch(Exception e) {
      logger.error("Error creating Guard encryption certificate metadata", e);
    }

    // <EntityDescriptor>/<AssertionConsumerService>
    IndexedEndpointType acs = spSSO.addNewAssertionConsumerService();
    acs.setIndex(0);
    acs.setBinding("urn:oasis:names:tc:SAML:1.0:profiles:browser-post");
    acs.setLocation("YOUR_ENGINE_URL/samlengine/shibb/acs");
    acs = spSSO.addNewAssertionConsumerService();
    acs.setIndex(1);
    acs.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    acs.setLocation("YOUR_ENGINE_URL/samlengine/s2/wbsso/acs");
    acs = spSSO.addNewAssertionConsumerService();
    acs.setIndex(2);
    acs.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
    acs.setLocation("YOUR_ENGINE_URL/samlengine/s2/wbsso/acs");

    // <EntityDescriptor>/<ContactPerson>
    ContactType contact = entityDescriptor.addNewContactPerson();
    contact.setContactType(ContactTypeType.TECHNICAL);
    contact.setCompany(form.getContactCompany());
    contact.setGivenName(form.getContactGivenName());
    contact.setSurName(form.getContactSurname());
    contact.setEmailAddressArray(new String[] {form.getContactEmail()});
    contact.setTelephoneNumberArray(new String[] {form.getContactPhone()});

    HashMap<String, String> ns = new HashMap<String, String>();
    ns.put("urn:guanxi:metadata", "gxmeta");

    XmlOptions xmlOptions = new XmlOptions();
    xmlOptions.setSavePrettyPrint();
    xmlOptions.setSavePrettyPrintIndent(2);
    xmlOptions.setUseDefaultNamespace();
    xmlOptions.setSaveAggressiveNamespaces();
    xmlOptions.setSaveSuggestedPrefixes(ns);
    xmlOptions.setSaveNamespacesFirst();
    try {
      entityDoc.save(new File(guardDir + File.separator + FileName.encode(form.getGuardid().toLowerCase()) + ".xml"), xmlOptions);
    }
    catch(Exception e) {
      logger.error(e);
    }
  }

  /**
   * Loads a new Guard's metadata and adds it to the list of those Guards
   * already loaded by the main Engine.
   *
   * @param guardMetadataFile Full path and name of the Guard's metadata file
   * @return true if loaded otherwise false if an error occurred
   */
  private boolean loadGuardMetadata(String guardMetadataFile) {
    try {
      EntityDescriptorDocument edDoc = EntityDescriptorDocument.Factory.parse(new File(guardMetadataFile));
      EntityDescriptorType entityDescriptor = edDoc.getEntityDescriptor();

      // Bung the Guard's SAML2 EntityDescriptor in the session under the Guard's entityID
      getServletContext().setAttribute(entityDescriptor.getEntityID(), entityDescriptor);

      logger.info("CA loaded new Guard : " + entityDescriptor.getEntityID());

      return true;
    }
    catch(Exception e) {
      logger.error("CA could not load new Guard", e);
      return false;
    }
  }

  /**
   * Encapsulates a certificate chain information. The class carries enough information
   * to be passed between specialised units to form a pipeline.
   */
  class CABean {
    /** An authenticated certificate chain */
    X509Certificate[] chain = null;
    /** The private key of the signing authority that produced the certificate chain */
    PrivateKey csrPrivateKey = null;

    /**
     * Sets the subject DN
     * @param subjectDN the dn of the subject of the chain
     */
    public void setSubjectDN(String subjectDN) {
      this.subjectDN = subjectDN;
    }

    String subjectDN = null;

    /**
     * Store the certificate chain in the bean
     * @param chain X509 certificate chain
     */
    public void setChain(X509Certificate[] chain) {
      this.chain = chain;
    }

    /**
     * Retrieve the certificate chain from the bean
     *
     * @return An array of X509Certificate instances
     */
    public X509Certificate[] getChain() {
      return chain;
    }

    /**
     * Returns the X509 certificate of the subject of the chain
     *
     * @return X509 certificate of the subject of the chain or null
     */
    public X509Certificate getSubjectCertificate() {
      String subjectCN = subjectDN.split(",")[0].split("=")[1];
      for (X509Certificate x509 : chain) {
        String[] parts = x509.getSubjectDN().getName().split(",");
        String x509CN = parts[parts.length - 1].split("=")[1];
        if (x509CN.equals(subjectCN)) {
          return x509;
        }
      }
      return null;
    }

    /**
     * Store the signing authority's private key in the bean. This must be the
     * private key that signed the chain that's stored in the bean.
     *
     * @param csrPrivateKey PrivateKey of the signing authority
     */
    public void setCSRPrivateKey(PrivateKey csrPrivateKey) {
      this.csrPrivateKey = csrPrivateKey;
    }

    /**
     * Retrieve the private key of the signing authority. This will be the private
     * key of the authority that signed the chain that's stored in the bean
     *
     * @return PrivateKey of the signing authority
     */
    public PrivateKey getCSRPrivateKey() {
      return csrPrivateKey;
    }
  }
}
