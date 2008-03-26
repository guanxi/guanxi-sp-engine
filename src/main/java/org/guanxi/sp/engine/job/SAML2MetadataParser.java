/* CVS Header
   $
   $
*/

package org.guanxi.sp.engine.job;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.guanxi.xal.saml_2_0.metadata.EntitiesDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;

public class SAML2MetadataParser implements Job {
  public SAML2MetadataParser() {}
  
  public void execute(JobExecutionContext context) throws JobExecutionException {
    // Get our custom config
    SAML2MetadataParserConfig config = (SAML2MetadataParserConfig)context.getJobDetail().getJobDataMap().get(GuanxiJobConfig.JOB_KEY_JOB_CONFIG);

    try {
      EntitiesDescriptorDocument doc = Utils.parseSAML2Metadata(config.getMetadataURL(), config.getWho());
      EntityDescriptorType[] entityDescriptors = doc.getEntitiesDescriptor().getEntityDescriptorArray();

      for (EntityDescriptorType entityDescriptor : entityDescriptors) {
        // Look for Identity Providers
        if (entityDescriptor.getIDPSSODescriptorArray().length > 0) {
          config.getLog().info("Loading IdP metadata for : " + entityDescriptor.getEntityID());
          config.getServletContext().setAttribute(entityDescriptor.getEntityID(), entityDescriptor);
        }
      }
    }
    catch(GuanxiException ge) {
      config.getLog().error("Error parsing metadata", ge);
    }
  }
}
