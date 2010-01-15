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
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;
import org.guanxi.common.job.ShibbolethSAML2MetadataParser;

import java.util.ArrayList;

public class SAML2MetadataParser extends ShibbolethSAML2MetadataParser implements Job {
  public SAML2MetadataParser() {}

  public void execute(JobExecutionContext context) throws JobExecutionException {
    // Get our custom config
    config = (SAML2MetadataParserConfig)context.getJobDetail().getJobDataMap().get(GuanxiJobConfig.JOB_KEY_JOB_CONFIG);

    init();

    // Only proceed if we loaded the metadata from either the URL or the cache
    if (doc == null) {
      logger.error("No metadata available");
      return;
    }

    if (config.getSigned()) {
      if (!verifyMetadataFingerprint()) {
        logger.error("Metadata fingerprint failed verification");
        return;
      }

      if (!verifyMetadataSignature()) {
        logger.error("Metadata signature failed verification");
        return;
      }
    }

    loadAndCacheEntities();

    EntityManager manager = loadEntityManager(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);

    try {
      // Store the new entity IDs for cleaning out old ones later
      ArrayList<String> newEntityIDs = new ArrayList<String>();

      if (!loadCAListFromMetadata(manager)) {
        logger.error("Failed to load root CA list from metadata");
        return;
      }

      for (EntityDescriptorType entityDescriptor : entityDescriptors) {
        // Look for Identity Providers
        if (entityDescriptor.getIDPSSODescriptorArray().length > 0) {
          logger.info("Loading IdP metadata for : " + entityDescriptor.getEntityID());

          Metadata metadataHandler = manager.createNewEntityHandler();
          // This will include AttributeAuthorityDescriptor nodes
          metadataHandler.setPrivateData(entityDescriptor);

          manager.addMetadata(metadataHandler);

          newEntityIDs.add(entityDescriptor.getEntityID());
        }
      }

      // Remove expired entities from the manager
      String[] oldEntityIDs = manager.getEntityIDs();
      for (String oldEntityID : oldEntityIDs) {
        if (!newEntityIDs.contains(oldEntityID)) {
          manager.removeMetadata(oldEntityID);
        }
      }
    }
    catch(GuanxiException ge) {
      logger.error("Could not get an entity handler from the metadata manager", ge);
    }
  }
}
