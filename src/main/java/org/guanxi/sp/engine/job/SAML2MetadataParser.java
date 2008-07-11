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

package org.guanxi.sp.engine.job;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.apache.log4j.Logger;
import org.guanxi.sp.engine.idp.IdPManager;
import org.guanxi.sp.engine.idp.UKFederationIdPMetadata;
import org.guanxi.xal.saml_2_0.metadata.EntitiesDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;

public class SAML2MetadataParser implements Job {
  public SAML2MetadataParser() {}
  
  public void execute(JobExecutionContext context) throws JobExecutionException {
	SAML2MetadataParserConfig config;
	String metadataURL;
	Logger logger;
	
	config = (SAML2MetadataParserConfig)context.getJobDetail().getJobDataMap().get(GuanxiJobConfig.JOB_KEY_JOB_CONFIG);
	metadataURL = config.getMetadataURL();
	logger = config.getLog();
	
	logger.info("Loading SAML2 metadata from: " + metadataURL);
	
	try {
		EntitiesDescriptorDocument doc;
		EntityDescriptorType[] entityDescriptors;
		IdPManager manager;
		
		doc = Utils.parseSAML2Metadata(metadataURL, config.getWho());
		entityDescriptors = doc.getEntitiesDescriptor().getEntityDescriptorArray();
		
		manager = IdPManager.getManager(config.getServletContext());
		manager.removeMetadata(metadataURL);
		
		for ( EntityDescriptorType currentMetadata : entityDescriptors ) {
			if ( currentMetadata.getIDPSSODescriptorArray().length > 0 ) {
				logger.info("Loading IdP metadata for : " + currentMetadata.getEntityID());
				manager.addMetadata(metadataURL, new UKFederationIdPMetadata(currentMetadata));
			}
		}
	}
	catch ( GuanxiException e ) {
		logger.error("Error parsing metadata", e);
	}
  }
}
