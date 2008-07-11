/**
 * 
 */
package org.guanxi.sp.engine.idp;

import org.guanxi.xal.saml_2_0.metadata.EndpointType;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.metadata.KeyDescriptorType;
import org.guanxi.xal.saml_2_0.metadata.KeyTypes;

/**
 * This is an implementation of the IdPMetadata interface that
 * supports wrapping the EntityDescriptorType. The EntityDescriptorType
 * works best with the metadata available from the UK Federation,
 * hence the name.
 * 
 * @author matthew
 *
 */
public class UKFederationIdPMetadata implements IdPMetadata {
	/**
	 * This stores the loaded IdP Metadata, and
	 * this class wraps around the data that this
	 * contains.
	 */
	private EntityDescriptorType idpMetadata;
	
	/**
	 * This creates a new wrapper class for the metadata provided.
	 * 
	 * @param idpMetadata
	 */
	public UKFederationIdPMetadata(EntityDescriptorType idpMetadata) {
		this.idpMetadata = idpMetadata;
	}
	
	/**
	 * This will return the entityID of the IdP.
	 */
	public String getEntityID() {
		return idpMetadata.getEntityID();
	}
	
	/**
	 * This will return the URL of the IdP Attribute Authority. This will attempt
	 * to get the Attribute Authority URL that corresponds to the 
	 * urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding binding. If this binding
	 * cannot be found then the first URL will be returned.
	 */
	// This should be updated to return the AA Url associated with the
	// correct binding - urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding
	
	// Example entry in metadata
	// <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">
	//     <AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://beta.athensams.net:5057/services/SAML11AttributeAuthority"/>
	// </AttributeAuthorityDescriptor>
	public String getAttributeAuthorityURL() {
		
		for ( EndpointType currentEndpoint : idpMetadata.getAttributeAuthorityDescriptorArray()[0].getAttributeServiceArray() ) {
			if ( currentEndpoint.getBinding().equals("urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding") ) {
				return currentEndpoint.getLocation();
			}
		}
		
		// this is currently left here because this is the old code and is the best guess when
		// no URL with the correct binding has been found
		return idpMetadata.getAttributeAuthorityDescriptorArray()[0].getAttributeServiceArray()[0].getLocation();
	}
	
	/**
	 * This will return the binary data associated with the signing certificate
	 * of the IdP. If this cannot find the signing certificate then the first
	 * certificate in the metadata will be returned.
	 */
	// KeyInfoType keyInfo = entityDescriptor.getAttributeAuthorityDescriptorArray()[0].getKeyDescriptorArray()[0].getKeyInfo();
    // X509DataType x509Data = keyInfo.getX509DataArray()[0];
    // byte[] bytes = x509Data.getX509CertificateArray()[0];
	public byte[] getX509Certificate() {
	    for ( KeyDescriptorType currentKey : idpMetadata.getAttributeAuthorityDescriptorArray()[0].getKeyDescriptorArray() ) {
	    	if ( currentKey.getUse() == KeyTypes.SIGNING ) {
	    		return currentKey.getKeyInfo().getX509DataArray()[0].getX509CertificateArray()[0];
	    	}
	    }
	    
	    // this is currently left here because this is the old code and is the best guess when
	    // no signing key can be found
	    return idpMetadata.getAttributeAuthorityDescriptorArray()[0].getKeyDescriptorArray()[0].getKeyInfo().getX509DataArray()[0].getX509CertificateArray()[0];
	}
}
