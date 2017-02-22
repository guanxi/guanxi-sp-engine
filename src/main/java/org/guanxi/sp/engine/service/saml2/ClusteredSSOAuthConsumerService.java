package org.guanxi.sp.engine.service.saml2;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.apache.xerces.util.URI;
import org.apache.xerces.util.URI.MalformedURIException;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.sp.Util;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.protocol.ResponseDocument;
import org.springframework.util.StringUtils;

/**
 * This class extends WebBrowserSSO to provide support
 * for clustered guards behind a single external SP entityid
 * 
 * The external entity id can be normal e.g. https://sp.example.com/saml2
 * 
 * Transparent guards behind the clustered external entityid must 
 * be in the form [internal guard id][delimiter][external entity id]
 * e.g. internal_guard_1::https://sp.example.com/saml2
 * 
 * @author rotis23
 */
public class ClusteredSSOAuthConsumerService extends WebBrowserSSOAuthConsumerService
{
	protected static final String DELIMITER = "::";
	
	private String delimiter = DELIMITER;
	
	@Override
	protected EntityDescriptorType getUnsolicitedGuard(HttpServletRequest request, String relayState)
			throws MalformedURIException, GuanxiException {
		
		//check first to see if there is a specified guard to use in request
		String guardID = request.getParameter(Guanxi.WAYF_PARAM_GUARD_ID);
		
		if(StringUtils.hasText(guardID)) {
			
			logger.info("Found a guard in the request: " + guardID);
			
			return (EntityDescriptorType) getServletContext().getAttribute(guardID);
		}
		else {
			URI uri = new URI(relayState);
			String clusterSPEntityId = getQueryMap(uri.getQueryString()).get("sp");
			
			logger.info("Trying to find guard for clustered entitid: " + clusterSPEntityId);
			
			Enumeration<?> e = getServletContext().getAttributeNames();
			
			while(e.hasMoreElements()) {
				guardID = (String)e.nextElement();
				
				logger.debug("Checking context name: " + guardID);
				
				if(guardID.endsWith(delimiter + clusterSPEntityId)) {
					
					logger.info("Found a random guard for cluster: " + guardID);
					
					return (EntityDescriptorType) getServletContext().getAttribute(guardID);
				}
			}
			
			throw new GuanxiException("Cannot determine a guard for clustered entityid:" + clusterSPEntityId);
		}
	}

	@Override
	protected ResponseDocument decryptResponse(
			ResponseDocument encryptedResponse,
			String entityId, GuardRoleDescriptorExtensions guardNativeMetadata)
			throws GuanxiException {

		if(entityId.contains(delimiter)) {
			
			logger.info("Found clustered entityid:" + entityId);
			
			//use the cluster external SP entity id to dycrypt the response
			String clusterSPEntityId = getClusterSPEntityId(entityId);
			EntityDescriptorType clusteredSPEntityDescriptor = (EntityDescriptorType) getServletContext().getAttribute(clusterSPEntityId);
			GuardRoleDescriptorExtensions clusteredSPNativeMetadata = Util.getGuardNativeMetadata(clusteredSPEntityDescriptor);
			
			return super.decryptResponse(encryptedResponse, clusterSPEntityId,
					clusteredSPNativeMetadata);
		}
		else
		{
			logger.info("Found NO clustered entityid:" + entityId);
		}
		
		return super.decryptResponse(encryptedResponse, entityId,
				guardNativeMetadata);
	}

	private String getClusterSPEntityId(String entityId) throws GuanxiException {
		if(entityId.contains(delimiter)) {
			return entityId.split(delimiter)[1];
		}
		
		throw new GuanxiException("Expected a clustered guard entity id");
	}

	public void setDelimiter(String delimiter) {
		this.delimiter = delimiter;
	}
}
