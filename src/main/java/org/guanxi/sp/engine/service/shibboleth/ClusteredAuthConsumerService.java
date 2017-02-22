package org.guanxi.sp.engine.service.shibboleth;

import org.guanxi.common.GuanxiException;
import org.guanxi.sp.Util;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;

/**
 * This class extends AuthConsumerService to provide support
 * for clustered guards behind a single external SP entityid
 * 
 * The external entity id can be normal e.g. https://sp.example.com/saml2
 * 
 * Transparent guards behind the clustered external entityid must 
 * be in the form [internal guard id][delimiter][external entity id]
 * e.g. internal_guard_1::https://sp.example.com/saml2
 * 
 * @author rotis23
 *
 */
public class ClusteredAuthConsumerService extends AuthConsumerService {
	private static final String DELIMITER = "::";
	
	private String delimiter = DELIMITER;

	@Override
	protected String getGuardEntrityId(EntityDescriptorType guardEntityDescriptor) throws GuanxiException {
		String guardID = guardEntityDescriptor.getEntityID();
		
		if(guardID.contains(delimiter)) {
			return getClusterSPEntityId(guardID);
		} else {
			return guardID;
		}
	}
	
	@Override
	protected GuardRoleDescriptorExtensions getGuardNativeMetadata(
			EntityDescriptorType guardEntityDescriptor,
			GuardRoleDescriptorExtensions guardNativeMetadata) throws GuanxiException {

		EntityDescriptorType clusteredSPEntityDescriptor = 
			(EntityDescriptorType) getServletContext().getAttribute(getGuardEntrityId(guardEntityDescriptor));
		return Util.getGuardNativeMetadata(clusteredSPEntityDescriptor);
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
