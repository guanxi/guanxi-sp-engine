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
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.xmlbeans.XmlOptions;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Logging;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.xal.saml_2_0.metadata.*;
import org.guanxi.xal.saml2.metadata.GuanxiGuardServiceDocument;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.sp.engine.Config;
import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.BindException;
import org.springframework.context.MessageSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
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
  private static Logger log = Logger.getLogger(RegisterGuardFormController.class);
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
    try {
      initLogger(getServletContext());
    }
    catch(GuanxiException ge) {
      throw new ServletException(ge);
    }

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
  public ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response,
                               Object command, BindException errors) throws ServletException {

    RegisterGuard form = (RegisterGuard)command;

    // Adjust the metadata directory for the new Guard
    String metadataDirectory = config.getGuardsMetadataDirectory() + Utils.SLASH + form.getGuardid().toLowerCase();

    // Create the new Guard metadata directory
    if (!createGuardMetadataDirectory(metadataDirectory)) {
      ModelAndView mAndV = new ModelAndView();
      mAndV.setViewName(errorView);
      mAndV.getModel().put(errorViewDisplayVar, messageSource.getMessage("register.guard.error.create.dir",
                                                                         null, request.getLocale()));
      return mAndV;
    }

    // Build an X509 name
    String x509DN = "CN=" + form.getGuardid();
    x509DN += ",OU=" + form.getOrgunit();
    x509DN += ",O=" + form.getOrg();
    x509DN += ",L=" + form.getCity();
    x509DN += ",ST=" + form.getLocality();
    x509DN += ",C=" + form.getCountry();

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
    String guardKeystore = metadataDirectory + Utils.SLASH + form.getGuardid().toLowerCase() + ".jks";
    createKeystoreWithChain(guardKeystore, form.getGuardid().toLowerCase(),
                            keystorePassword, caBean);

    createGuardMetadataFile(metadataDirectory, guardKeystore, keystorePassword, form);

    // Load the new Guard so the main Engine can use it
    loadGuardMetadata(metadataDirectory + Utils.SLASH + form.getGuardid().toLowerCase() + ".xml");

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
        log.error("Can't get root certificate from CA keystore");
        return null;
      }
      PrivateKey rootPrivKey = (PrivateKey)rootKS.getKey(rootCAKeystoreAlias, rootCAKeystorePassword.toCharArray());
      X509Certificate[] signedChain = createSignedCert(rootCert, rootPrivKey, csr, keyType);

      //...package up the result...
      CABean caBean = new CABean();
      caBean.setChain(signedChain);
      caBean.setCSRPrivateKey(clientPrivateKey);

      // ...and send it back
      return caBean;
    }
    catch(Exception e) {
      log.error(e);
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
      log.error(e);
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
        log.error("Unrecognised key type : " + keyType);
        return null;
      }

    }
    catch(Exception e) {
      log.error(e);
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
      log.error(e);
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
      log.error(e);
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
      log.error(e);
      try {
        request.setAttribute("ERROR_ID", "ID_NEED_ALL_PARAMETERS");
        request.setAttribute("ERROR_MESSAGE", e.getMessage());
        request.getRequestDispatcher("/guanxi_sp/sp_error.jsp").forward(request, response);
      }
      catch(Exception ex) {
        log.error(e);
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
   */
  private void createGuardMetadataFile(String guardDir, String keystore, String keystorePassword,
                                       RegisterGuard form) {
    EntityDescriptorDocument entityDoc = EntityDescriptorDocument.Factory.newInstance();
    EntityDescriptorType entityDescriptor = entityDoc.addNewEntityDescriptor();

    entityDescriptor.setEntityID(form.getGuardid().toLowerCase());

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

    // <EntityDescriptor>/<ContactPerson>
    ContactType contact = entityDescriptor.addNewContactPerson();
    contact.setContactType(ContactTypeType.TECHNICAL);
    contact.setCompany(form.getContactCompany());
    contact.setGivenName(form.getContactGivenName());
    contact.setSurName(form.getContactSurname());
    contact.setEmailAddressArray(new String[] {form.getContactEmail()});
    contact.setTelephoneNumberArray(new String[] {form.getContactPhone()});

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

    HashMap ns = new HashMap();
    ns.put("urn:guanxi:metadata", "gxmeta");

    XmlOptions xmlOptions = new XmlOptions();
    xmlOptions.setSavePrettyPrint();
    xmlOptions.setSavePrettyPrintIndent(2);
    xmlOptions.setUseDefaultNamespace();
    xmlOptions.setSaveAggressiveNamespaces();
    xmlOptions.setSaveSuggestedPrefixes(ns);
    xmlOptions.setSaveNamespacesFirst();
    try {
      entityDoc.save(new File(guardDir + Utils.SLASH + form.getGuardid().toLowerCase() + ".xml"), xmlOptions);
    }
    catch(Exception e) {
      log.error(e);
    }
  }

  private void initLogger(ServletContext context) throws GuanxiException {
    DOMConfigurator.configure(context.getRealPath("/WEB-INF/config/sp-log4j.xml"));

    PatternLayout defaultLayout = new PatternLayout(Logging.DEFAULT_LAYOUT);

    RollingFileAppender rollingFileAppender = new RollingFileAppender();
    rollingFileAppender.setName("GuanxiEngine");
    try {
      rollingFileAppender.setFile(context.getRealPath(Logging.DEFAULT_SP_ENGINE_LOG_DIR + "guanxi-sp-engine-ca.log"), true, false, 0);
    }
    catch(IOException ioe) {
      throw new GuanxiException(ioe);
    }
    rollingFileAppender.setMaxFileSize("1MB");
    rollingFileAppender.setMaxBackupIndex(5);
    rollingFileAppender.setLayout(defaultLayout);

    log.removeAllAppenders();
    log.addAppender(rollingFileAppender);
    log.setAdditivity(false);
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

      log.info("CA loaded new Guard : " + entityDescriptor.getEntityID());

      return true;
    }
    catch(Exception e) {
      log.error("CA could not load new Guard", e);
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
