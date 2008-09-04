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
import org.guanxi.xal.saml_2_0.metadata.EntitiesDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;

public class SAML2MetadataParser implements Job {
  /** Our logger */
  private static final Logger logger = Logger.getLogger(SAML2MetadataParser.class.getName());

  public SAML2MetadataParser() {}

  public void execute(JobExecutionContext context) throws JobExecutionException {
    // Get our custom config
    SAML2MetadataParserConfig config = (SAML2MetadataParserConfig)context.getJobDetail().getJobDataMap().get(GuanxiJobConfig.JOB_KEY_JOB_CONFIG);

    EntitiesDescriptorDocument doc = null;
    try {
      // Load the metadata from the URL
      doc = Utils.parseSAML2Metadata(config.getMetadataURL(), config.getWho());
    }
    catch(GuanxiException ge) {
      logger.error("Error parsing metadata. Loading from cache", ge);
      try {
        // Load the metadata from the cache
        doc = Utils.parseSAML2Metadata("file:///" + config.getMetadataCacheFile(), config.getWho());
      }
      catch(GuanxiException gex) {
        logger.error("Could not load metadata from cache : " + config.getMetadataCacheFile(), gex);
      }
    }

    // Only proceed if we loaded the metadata from either the URL or the cache
    if (doc == null) {
      logger.error("No metadata available");
      return;
    }

    EntityDescriptorType[] entityDescriptors = doc.getEntitiesDescriptor().getEntityDescriptorArray();

    // Cache the metadata locally
    try {
      Utils.writeSAML2MetadataToDisk(doc, config.getMetadataCacheFile());
    }
    catch(GuanxiException ge) {
      logger.error("Could not cache metadata to : " + config.getMetadataCacheFile(), ge);
    }

    EntityFarm farm = (EntityFarm)config.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_IDP_ENTITY_FARM);
    EntityManager manager = farm.getEntityManagerForSource(config.getMetadataURL());
    manager.removeMetadata();

    //@todo setup TrustEngine and PKIX validation certs

    try {
      for (EntityDescriptorType entityDescriptor : entityDescriptors) {
        // Look for Service Providers
        if (entityDescriptor.getIDPSSODescriptorArray().length > 0) {
          logger.info("Loading IdP metadata for : " + entityDescriptor.getEntityID());

          Metadata metadataHandler = manager.createNewEntityHandler();
          // This will include AttributeAuthorityDescriptor nodes
          metadataHandler.setPrivateData(entityDescriptor);

          manager.addMetadata(metadataHandler);
        }
      }
    }
    catch(GuanxiException ge) {
      logger.error("Could not get an entity handler from the metadata manager", ge);
    }
  }
}
