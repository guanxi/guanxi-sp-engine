/**
 * 
 */
package org.guanxi.sp.engine.idp;

/**
 * This provides an interface to access all of the different attributes of
 * the IdP Metadata that are required by Guanxi. Using this means that 
 * different formats of metadata can be supported much more easily.
 * 
 * @author matthew
 *
 */
// The comments like this give examples of code that the method call can replace
// assuming you are using the UKFederationIdPMetadata class.
public interface IdPMetadata {
	
	/**
	 * This will return the entityID of the IdP.
	 * @return
	 */
	// metadata.getEntityID()
	public String getEntityID();
	
	/**
	 * This gets the Attribute Authority URL. Where possible this should get the
	 * AAURL that has the urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding binding.
	 * @return
	 */
	// idPMetadata.getAttributeAuthorityDescriptorArray()[0].getAttributeServiceArray()[0].getLocation();
	public String getAttributeAuthorityURL();
	
	/**
	 * This gets the binary data of the signing certificate used by the IdP.
	 */
	// KeyInfoType keyInfo = entityDescriptor.getAttributeAuthorityDescriptorArray()[0].getKeyDescriptorArray()[0].getKeyInfo();
    // X509DataType x509Data = keyInfo.getX509DataArray()[0];
    // byte[] bytes = x509Data.getX509CertificateArray()[0];
	public byte[] getX509Certificate();
	
	
}
