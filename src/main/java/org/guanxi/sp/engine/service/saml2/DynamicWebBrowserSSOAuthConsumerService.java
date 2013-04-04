package org.guanxi.sp.engine.service.saml2;

import org.apache.log4j.Logger;
import org.guanxi.common.EntityConnection;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.sp.engine.Config;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;

/**
 * This class extends WebBrowserSSO to provide support
 * for systems with multitenancy (dynamic domains)
 * 
 * Use DYNAMIC_GUARD_DOMAIN in the guard Podder URL 
 * e.g. http://DYNAMIC_GUARD_DOMAIN/guard.guanxiGuardPodder
 * 
 * Use cookie.domain=.DYNAMIC_GUARD_DOMAIN in the guard config
 * 
 * The engine will ask the guard what external multitenancy domain to use 
 * 
 * @author rotis23
 */
public class DynamicWebBrowserSSOAuthConsumerService extends ClusteredSSOAuthConsumerService
{
	protected final Logger logger = Logger.getLogger(getClass());
	
	private String guardDomainPlaceholder = "DYNAMIC_GUARD_DOMAIN";
	
	protected String getPodderURL(String sessionID, Config config, GuardRoleDescriptorExtensions guardNativeMetadata) throws GuanxiException
	{
		logger.info("getPodderURL: entry");
		String podderURL = guardNativeMetadata.getPodderURL();
		
		// build the query to retrieve the appropriate dynamic domain
	    String queryString = guardNativeMetadata.getVerifierURL() + "?" +
	                         Guanxi.SESSION_VERIFIER_PARAM_SESSION_ID + "=" +
	                         sessionID + "&" + "dynamicDomainNameRequest=true";

		EntityConnection verifierService = new EntityConnection(queryString,
				config.getCertificateAlias(), // alias of cert
				config.getKeystore(),
				config.getKeystorePassword(),
				config.getTrustStore(),
				config.getTrustStorePassword(),
				EntityConnection.PROBING_OFF);
		verifierService.setDoOutput(true);
		verifierService.connect();
		String dynamicDomainNameResult = verifierService.getContentAsString();
		
		logger.info("getPodderURL: found dynamicDomainNameResult: " + dynamicDomainNameResult);

		logger.info("getPodderURL: found podderURL: " + podderURL);
		
		//update the podder URL so that we go to the correct dynamic domain
		String dynamicPodderURLFromGuard = podderURL.replace(guardDomainPlaceholder, dynamicDomainNameResult);
		
		logger.info("getPodderURL: exit: dynamic podderURL: " + dynamicPodderURLFromGuard);
		
		return dynamicPodderURLFromGuard;
	}

}
