/**
 * 
 */
package org.guanxi.sp.engine.service.shibboleth;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.guanxi.common.EntityConnection;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Utils;
import org.guanxi.common.definitions.Shibboleth;
import org.guanxi.xal.saml_1_0.assertion.NameIdentifierType;
import org.guanxi.xal.saml_1_0.assertion.SubjectType;
import org.guanxi.xal.saml_1_0.protocol.AttributeQueryType;
import org.guanxi.xal.saml_1_0.protocol.RequestDocument;
import org.guanxi.xal.saml_1_0.protocol.RequestType;
import org.guanxi.xal.saml_1_0.protocol.ResponseType;
import org.guanxi.xal.soap.Body;
import org.guanxi.xal.soap.Envelope;
import org.guanxi.xal.soap.EnvelopeDocument;
import org.guanxi.xal.soap.Header;
import org.springframework.web.servlet.ModelAndView;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This is a thread that can be used to perform the ACS process in the background.
 * This is associated with a session and will set the ModelAndView to return upon
 * completion. Using a thread like this allows the 
 * 
 * @author matthew
 *
 */
public class AuthConsumerServiceThread implements Runnable {
  /**
   * This is the logger that this will use. This is set to use the
   * AuthConsumerService logger because this thread is a way to allow
   * feedback on that process while it is being executed.
   */
  private static final Logger logger = Logger.getLogger(AuthConsumerService.class.getName());
  
  /**
   * These are the fixed states to indicate the current progress.
   * These should be coupled with a progress indicator and text.
   */
  private static final ModelAndView preparingAARequest, readingAAResponse, preparingGuardRequest, readingGuardResponse;
  /**
   * This is the key that is used to store the Integer that indicates
   * the approximate progress of this thread in the ModelAndView.
   */
  public static final String progressPercentKey = "percent";
  /**
   * This is the key that is used to store the String that describes
   * the current operation being performed in the ModelAndView.
   */
  public static final String progressTextKey    = "text";
  
  static {
    preparingAARequest    = new ModelAndView();
    readingAAResponse     = new ModelAndView();
    preparingGuardRequest = new ModelAndView();
    readingGuardResponse  = new ModelAndView();
    
    preparingAARequest.addObject(progressPercentKey, new Integer(0));
    preparingAARequest.addObject(progressTextKey, "Preparing AA Request");
    
    readingAAResponse.addObject(progressPercentKey, new Integer(25));
    readingAAResponse.addObject(progressTextKey, "Communicating with AA");
    
    preparingGuardRequest.addObject(progressPercentKey, new Integer(50));
    preparingGuardRequest.addObject(progressTextKey, "Preparing Guard Request");
    
    readingGuardResponse.addObject(progressPercentKey, new Integer(75));
    readingGuardResponse.addObject(progressTextKey, "Communicating with Guard");
  }
  
  /**
   * This is the object that spawned this thread and is used to reference
   * various variables that have been set in it.
   */
  private AuthConsumerService parent;
  /**
   * This is the session according to the guard.
   * This is used in some of the communication between
   * the engine and the guard, and this is NOT the
   * session to which this thread is tied.
   */
  private String guardSession;
  /**
   * This is the URL of the attribute consumer service
   * on the Guard.
   */
  private String acsURL;
  /**
   * This is the URL of the Attribute Authority on the IdP.
   */
  private String aaURL;
  /**
   * This is the URL of the Podder on the Guard.
   */
  private String podderURL;
  /**
   * This is the entityID of the guard and is used in communications
   * with the IdP.
   */
  private String entityID;
  /**
   * This is the keystore file which contains the client certificates used to
   * communicate with the IdP and with the Guard.
   */
  private String keystoreFile;
  /**
   * This is the password for the keystore.
   */
  private String keystorePassword;
  /**
   * This is the truststore file which contains the certificates for the IdP
   * and the Guard. These are used to verify that the IdP and the Guard are
   * authentic.
   */
  private String truststoreFile;
  /**
   * This is the password for the truststore.
   */
  private String truststorePassword;
  /**
   * This is the IdP's provider Id.
   */
  private String idpProviderId;
  /**
   * This is the IdP's name identifier.
   */
  private String idpNameIdentifier;
  /**
   * This holds the SAML response coming from an IdP
   */
  private ResponseType samlResponse;
  /**
   * This is a very important variable which is used to
   * communicate state. This must always be accessed through
   * the methods, even within this class. This is because
   * those methods are synchronised and as such not using them
   * risks race conditions.
   * 
   * This is accessed by different threads - it is set by the
   * one associated with this object, and is read by the one
   * associated with the HttpRequest.
   */
  private volatile ModelAndView status;
  /**
   * This indicates if the thread has come to an end and can be
   * discarded. Since the status is always a valid object the nullness
   * of it cannot be tested for to determine this state. Also, assumptions
   * about the content of 'in progress' status objects should not be 
   * used to replace this as the structure of them may change.
   */
  private volatile boolean completed;
  
  /**
   * This creates an AuthConsumerServiceThread that can be used
   * to retrieve the attributes from the AA URL and then pass them
   * to the Guard.
   * 
   * @param parent              This is the AuthConsumerService object that has spawned this object.
   * @param guardSession        This is the Guard Session string that has been passed to the Engine.
   * @param acsURL              This is the URL of the Attribute Consumer Service on the Guard.
   * @param aaURL               This is the URL of the Attribute Authority on the IdP.
   * @param podderURL           This is the URL of the Podder Service on the Guard.
   * @param entityID            This is the entityID of the Guard that will be used when talking to the IdP.
   * @param keystoreFile        This is the location of the KeyStore which will be used to authenticate the client in secure communications.
   * @param keystorePassword    This is the password for the KeyStore file.
   * @param truststoreFile      This is the TrustStore file which will be used to authenticate the server in secure communications.
   * @param truststorePassword  This is the password for the TrustStore file.
   * @param idpProviderId       This is the providerId for the IdP that provides the Attributes.
   * @param idpNameIdentifier   This is the name identifier that the IdP requires.
   * @param samlResponse        This is the initial SAML response from the IdP that confirmed that the user had logged in.
   */
  public AuthConsumerServiceThread(AuthConsumerService parent, String guardSession, String acsURL, String aaURL, 
                                   String podderURL, String entityID, String keystoreFile, String keystorePassword, 
                                   String truststoreFile, String truststorePassword, String idpProviderId, 
                                   String idpNameIdentifier, ResponseType samlResponse) {
    this.parent             = parent;
    this.guardSession       = guardSession;
    this.acsURL             = acsURL;
    this.aaURL              = aaURL;
    this.podderURL          = podderURL;
    this.entityID           = entityID;
    this.keystoreFile       = keystoreFile;
    this.truststoreFile     = truststoreFile;
    this.truststorePassword = truststorePassword;
    this.idpProviderId      = idpProviderId;
    this.idpNameIdentifier  = idpNameIdentifier;
    this.samlResponse       = samlResponse;
  }
  
  /**
   * This sets the ModelAndView, and should be called solely by
   * this class, hence the access limit. The status object should
   * only ever be set by this method to preserve the synchronised
   * status correctly.
   * 
   * @param status
   */
  private synchronized void setStatus(ModelAndView status) {
    this.status = status;
  }
  /**
   * This gets the ModelAndView that can be used to display the current
   * status of the process. 
   * 
   * @return
   */
  public synchronized ModelAndView getStatus() {
    return status;
  }
  /**
   * This sets the completed flag. When this has been set to true this thread
   * has concluded and should be discarded, and the ModelAndView returned by
   * {@link #getStatus()} will be the final result.
   * 
   * @param completed
   */
  private synchronized void setCompleted(boolean completed) {
    this.completed = completed;
  }
  /**
   * This reads the completed flag. When this has been set to true this thread
   * has concluded and should be discarded, and the ModelAndView returned by
   * {@link #getStatus()} will be the final result.
   * 
   * @return
   */
  public synchronized boolean isCompleted() {
    return completed;
  }
  

  /**
   * This prepares the request to the IdP for the attributes.
   * 
   * @param request   The initial request object
   * @param entityID  The entityID of the guard to use when communicating with the Attribute Authority
   * @return          An EnvelopeDocument containing the SOAP request
   */
  private EnvelopeDocument prepareAARequest(String idpProviderId, String idpNameIdentifier, String entityID) {
    RequestDocument    samlRequestDoc;
    RequestType        samlRequest;
    AttributeQueryType attrQuery;
    SubjectType        subject;
    NameIdentifierType nameID;
    EnvelopeDocument   soapEnvelopeDoc;
    Envelope           soapEnvelope;
    Body               soapBody;

    // Build a SAML Request to get attributes from the IdP
    samlRequestDoc = RequestDocument.Factory.newInstance();
    samlRequest    = samlRequestDoc.addNewRequest();
    samlRequest.setRequestID(Utils.createNCNameID());
    samlRequest.setMajorVersion(new BigInteger("1"));
    samlRequest.setMinorVersion(new BigInteger("1"));
    samlRequest.setIssueInstant(Calendar.getInstance());
    Utils.zuluXmlObject(samlRequest, 0);

    // Add an attribute query to the SAML request
    attrQuery = samlRequest.addNewAttributeQuery();
    attrQuery.setResource(entityID);
    subject   = attrQuery.addNewSubject();
    nameID    = subject.addNewNameIdentifier();
    nameID.setFormat(Shibboleth.NS_NAME_IDENTIFIER);
    nameID.setNameQualifier(idpProviderId);
    nameID.setStringValue(idpNameIdentifier);

    // Put the SAML request and attribute query in a SOAP message
    soapEnvelopeDoc = EnvelopeDocument.Factory.newInstance();
    soapEnvelope    = soapEnvelopeDoc.addNewEnvelope();
    soapBody        = soapEnvelope.addNewBody();

    soapBody.getDomNode().appendChild(soapBody.getDomNode().getOwnerDocument().importNode(samlRequest.getDomNode(), true));
    
    return soapEnvelopeDoc;
  }
  
  /**
   * This opens an AA connection to the indicated IdP, sends the SOAP request, and then reads the result.
   * 
   * @param aaURL               The URL to connect to
   * @param entityID            The entity ID of the guard to use (used to load the correct certificate from the keystore)
   * @param keystoreFile        The location of the keystore file for the client certificates
   * @param keystorePassword    The password for the keystore file
   * @param truststoreFile      The location of the truststore file to use to verify the server certificates
   * @param truststorePassword  The password for the truststore file
   * @param soapRequest         The soap request to write to the Attribute Authority
   * @return                    The response from the Attribute Authority
   * @throws GuanxiException    If there is a problem creating the connection or setting the attributes for the connection
   * @throws IOException        If there is a problem reading from or writing to the connection
   */
  private String processAAConnection(String aaURL, String entityID, String keystoreFile, String keystorePassword, 
                                     String truststoreFile, String truststorePassword, EnvelopeDocument soapRequest) 
                                     throws GuanxiException, IOException {
    EntityConnection connection;

    connection = new EntityConnection(aaURL, entityID, keystoreFile, keystorePassword, truststoreFile, truststorePassword, EntityConnection.PROBING_OFF);

    connection.setDoOutput(true);
    connection.setRequestProperty("Content-type", "text/xml");
    try {
      connection.connect();
    }
    catch ( Exception e ) {
      /*
       * This is a special case. There are certain IdPs that have attribute authority URLs
       * that ask for a client certificate but reject any that I have provided. However if
       * a connection is made to them providing no client certificate then there is no problem.
       * passing "" as the keystore location prevents the loading of the client certificate
       * silently - which is bad - but is the desired behaviour at this point.
       * 
       * TODO: Add flag to indicate non-client-certificate AA URLs, and handle it
       * TODO: Add new constructor for EntityConnection which does not load the client certificate
       * TODO: Stop doing this! If the client certificate is requested then it should be provided.
       */
      connection = new EntityConnection(aaURL, truststoreFile, truststorePassword, EntityConnection.PROBING_OFF);
      connection.setDoOutput(true);
      connection.setRequestProperty("Content-type", "text/xml");
      connection.connect();
    }
    soapRequest.save(connection.getOutputStream());
    return new String(Utils.read(connection.getInputStream()));
  }
  
  /**
   * This prepares the response to the guard regarding the AA process.
   * 
   * @param request       The original request object
   * @param guardSession  The string indicating the guard session to use
   * @param aaURL         The Attribute Authority URL which was just used to get the attributes
   * @param aaResponse    The response from talking to the Attribute Authority
   * @return              An EnvelopeDocument that must be sent to the Guard
   * @throws XmlException If there is a problem parsing the aaResponse
   */
  private EnvelopeDocument prepareGuardRequest(ResponseType samlResponse, String guardSession, String aaURL, String aaResponse) throws XmlException {
    EnvelopeDocument soapEnvelopeDoc;
    Envelope         soapEnvelope;
    
    soapEnvelopeDoc = EnvelopeDocument.Factory.parse(aaResponse);

    soapEnvelope = soapEnvelopeDoc.getEnvelope();

    // Before we send the SAML Response from the AA to the Guard, add the Guanxi SOAP header
    Header soapHeader = soapEnvelope.addNewHeader();
    Element gx = soapHeader.getDomNode().getOwnerDocument().createElementNS("urn:guanxi:sp", "GuanxiGuardSessionID");
    Node gxNode = soapHeader.getDomNode().appendChild(gx);
    org.w3c.dom.Text gxTextNode = soapHeader.getDomNode().getOwnerDocument().createTextNode(guardSession);
    gxNode.appendChild(gxTextNode);
  
    // Add the SAML Response from the IdP to the SOAP headers
    Header authHeader = soapEnvelope.addNewHeader();
    Element auth = authHeader.getDomNode().getOwnerDocument().createElementNS("urn:guanxi:sp", "AuthnFromIdP");
    auth.setAttribute("aa", aaURL);
    Node authNode = authHeader.getDomNode().appendChild(auth);
    authNode.appendChild(authNode.getOwnerDocument().importNode(samlResponse.getDomNode(), true));

    return soapEnvelopeDoc;
  }
  
  /**
   * This opens the connection to the guard, sends the SOAP request, and reads the response.
   * 
   * @param acsURL              The URL of the Guard Attribute Consumer Service
   * @param entityID            The entity ID of the Guard
   * @param keystoreFile        The location of the keystore to use to identify the engine to the guard
   * @param keystorePassword    The password for the keystore
   * @param truststoreFile      The location of the truststore to use to verify the guard
   * @param truststorePassword  The password for the truststore
   * @return                    A string containing the response from the guard
   * @throws GuanxiException    If there is a problem creating the EntityConnection or setting the attributes on it
   * @throws IOException        If there is a problem using the EntityConnection to read or write data
   */
  private String processGuardConnection(String acsURL, String entityID, String keystoreFile, String keystorePassword, String truststoreFile, String truststorePassword, EnvelopeDocument soapRequest) throws GuanxiException, IOException {
    EntityConnection connection;
    
    // Initialise the connection to the Guard's attribute consumer service
    connection = new EntityConnection(acsURL, entityID, keystoreFile, keystorePassword, truststoreFile, truststorePassword, EntityConnection.PROBING_OFF);
    connection.setDoOutput(true);
    connection.connect();

    // Send the AA's SAML Response as-is to the Guard's attribute consumer service...
    soapRequest.save(connection.getOutputStream());
    
    // ...and read the response from the Guard
    return new String(Utils.read(connection.getInputStream()));
  }

  @SuppressWarnings("unchecked")
  public void run() {
    ModelAndView mAndV;
    String       aaResponse, guardResponse;
    EnvelopeDocument aaSoapRequest, guardSoapRequest;
    
    mAndV = new ModelAndView();
    
    // done getting configuration information, lets make the connection to the AA

    setStatus(preparingAARequest);
    aaSoapRequest = prepareAARequest(idpProviderId, idpNameIdentifier, entityID);

    setStatus(readingAAResponse);
    try {
      aaResponse = processAAConnection(aaURL, entityID, keystoreFile, keystorePassword, truststoreFile, truststorePassword, aaSoapRequest); // no close, so no finally
    }
    catch ( Exception e ) {
      logger.error("AA connection error", e);
      mAndV.setViewName(parent.getErrorView());
      mAndV.getModel().put(parent.getErrorViewDisplayVar(), e.getMessage());
      
      setStatus(mAndV);
      setCompleted(true);
      return;
    }
    
    // done with the connection to the AA, lets talk to the Guard
    
    setStatus(preparingGuardRequest);
    try {
      guardSoapRequest = prepareGuardRequest(samlResponse, guardSession, aaURL, aaResponse);
    }
    catch ( XmlException e ) { // this is caused by parsing the AA response, and so is a problem with the attribute authority not the guard
      logger.error("AA SAML Response parse error", e);
      logger.error("SOAP response:");
      logger.error("------------------------------------");
      logger.error(aaResponse);
      logger.error("------------------------------------");
      mAndV.setViewName(parent.getErrorView());
      mAndV.getModel().put(parent.getErrorViewDisplayVar(), e.getMessage());
      
      setStatus(mAndV);
      setCompleted(true);
      return;
    }
    
    setStatus(readingGuardResponse);
    try {
      guardResponse = processGuardConnection(acsURL, entityID, keystoreFile, keystorePassword, truststoreFile, truststorePassword, guardSoapRequest);
    }
    catch ( Exception e ) {
      logger.error("Guard ACS connection error", e);
      mAndV.setViewName(parent.getErrorView());
      mAndV.getModel().put(parent.getErrorViewDisplayVar(), e.getMessage());
      
      setStatus(mAndV);
      setCompleted(true);
      return;
    }
    
    // Done talking to the guard. Parse the response to ensure that it is valid and then redirect to the Podder
    
    try {
      EnvelopeDocument.Factory.parse(guardResponse);
    }
    catch(XmlException xe) {
      logger.error("Guard ACS response parse error", xe);
      logger.error("SOAP response:");
      logger.error("------------------------------------");
      logger.error(guardResponse);
      logger.error("------------------------------------");
      mAndV.setViewName(parent.getErrorView());
      mAndV.getModel().put(parent.getErrorViewDisplayVar(), xe.getMessage());
      
      setStatus(mAndV);
      setCompleted(true);
      return;
    }
    
    mAndV.setViewName(parent.getPodderView());
    mAndV.getModel().put("podderURL", podderURL + "?id=" + guardSession);
    
    setStatus(mAndV);
    setCompleted(true);
  }
}
