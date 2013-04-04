package org.guanxi.sp.engine.service.generic;

import javax.servlet.http.HttpServletRequest;

import org.guanxi.common.GuanxiException;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.sp.Util;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.springframework.web.servlet.ModelAndView;

/**
 * This class extends GenericProfileService to provide support
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
public class ClusteredGenericProfileService extends GenericProfileService
{
	private static final String DELIMITER = "::";
	
	private String delimiter = DELIMITER;

	@Override
	protected ModelAndView doProfile(HttpServletRequest request,
			ProfileService profileService, String guardID,
			String guardSessionID,
			GuardRoleDescriptorExtensions guardNativeMetadata, String entityID,
			EntityFarm farm) throws GuanxiException {

		if(guardID.contains(delimiter)) {
			
			logger.info("Found clustered entityid for guardID:" + guardID);
			
			String clusterSPEntityId = getClusterSPEntityId(guardID);
			
			logger.info("Found clustered entityid:" + clusterSPEntityId);
			
			//use the cluster external SP entity id to do the profile request
			EntityDescriptorType clusteredSPEntityDescriptor = (EntityDescriptorType) getServletContext().getAttribute(clusterSPEntityId);
			GuardRoleDescriptorExtensions clusteredSPNativeMetadata = Util.getGuardNativeMetadata(clusteredSPEntityDescriptor);
			
			return super.doProfile(request, profileService, clusterSPEntityId, guardSessionID,
					clusteredSPNativeMetadata, entityID, farm);
		}
		else
		{
			logger.info("Found NO clustered entityid:" + guardID);
		}
		
		return super.doProfile(request, profileService, guardID, guardSessionID,
				guardNativeMetadata, entityID, farm);
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
