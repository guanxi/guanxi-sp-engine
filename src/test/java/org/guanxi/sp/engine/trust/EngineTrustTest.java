/* CVS Header
   $
   $
*/

package org.guanxi.sp.engine.trust;

import org.junit.Test;
import org.junit.Assert;
import static org.junit.Assert.fail;
import org.springframework.web.context.support.XmlWebApplicationContext;
import org.guanxi.sp.engine.EngineTest;
import org.guanxi.sp.engine.job.SAML2MetadataParser;
import org.guanxi.common.trust.TrustEngine;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.metadata.IdPMetadata;
import org.guanxi.xal.saml_1_0.protocol.ResponseDocument;
import org.quartz.*;
import org.quartz.spi.TriggerFiredBundle;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.impl.calendar.BaseCalendar;

import java.io.File;
import java.util.HashMap;

public class EngineTrustTest extends EngineTest {
  @Test
  public void trustTest() {
    try {
      // Initialise Spring
      XmlWebApplicationContext ctx = new XmlWebApplicationContext();
      ctx.setConfigLocations(metadataConfigFiles);
      ctx.setServletContext(servletContext);
      ctx.refresh();

      // Get the parser job from Spring and reconfigure it with the test settings
      SAML2MetadataParserConfig config = (SAML2MetadataParserConfig)ctx.getBean("spUKFederationMetadataParser");
      String metadataURL = "file:///" + new File(EngineTrustTest.class.getResource("/metadata.xml").getPath()).getCanonicalPath();
      config.setMetadataURL(metadataURL);
      config.setWho("TEST");
      config.setKey("TEST_KEY");
      config.setCronLine("10 0/59 * * * ?");
      config.setServletContext(servletContext);
      config.init();

      // Get the metdata farm from Spring and reconfigure it with the test settings
      EntityFarm farm = (EntityFarm)ctx.getBean("spEntityFarm");
      HashMap<String, EntityManager> managers = new HashMap<String, EntityManager>();
      managers.put(metadataURL, (EntityManager)ctx.getBean("spSAML2EntityManager"));
      farm.setEntityManagers(managers);
      servletContext.setAttribute(Guanxi.CONTEXT_ATTR_IDP_ENTITY_FARM, farm);

      // Initialise the test job settings
      JobDetail jobDetail = new JobDetail("TEST_KEY", Scheduler.DEFAULT_GROUP,
                                          Class.forName("org.guanxi.sp.engine.job.SAML2MetadataParser"));
      JobDataMap jobDataMap = new JobDataMap();
      jobDataMap.put(GuanxiJobConfig.JOB_KEY_JOB_CONFIG, config);
      jobDetail.setJobDataMap(jobDataMap);

      // Get Quartz ready
      Trigger trigger = new CronTrigger(config.getKey(), Scheduler.DEFAULT_GROUP);
      Scheduler scheduler = new StdSchedulerFactory().getScheduler();

      // Get a new bundle ready. We don't care about dates as we'll run the job manually
      TriggerFiredBundle bundle = new TriggerFiredBundle(jobDetail, trigger, new BaseCalendar(),
                                                         false, null, null, null, null);

      // Get the job and its context ready...
      SAML2MetadataParser parserJob = new SAML2MetadataParser();
      // ...and run the job
      parserJob.execute(new JobExecutionContext(scheduler, bundle, new SAML2MetadataParser()));

      File metadataCacheFile = new File(config.getMetadataCacheFile());
      Assert.assertTrue(metadataCacheFile.exists());
      metadataCacheFile.delete();

      EntityManager manager = farm.getEntityManagerForSource(metadataURL);
      Assert.assertNotNull(manager);

      manager = farm.getEntityManagerForID("urn:bond:hq");
      Assert.assertNotNull(manager);

      IdPMetadata idpMetadata = (IdPMetadata)manager.getMetadata("urn:bond:hq");
      Assert.assertNotNull(idpMetadata);
      Assert.assertEquals("urn:bond:hq", idpMetadata.getEntityID());

      /*
      String mockSamlResponseFile = "file:///" + new File(EngineTrustTest.class.getResource("/samlresponse.xml").getPath()).getCanonicalPath();
      ResponseDocument mockSamlResponseDoc = ResponseDocument.Factory.parse(mockSamlResponseFile);

      TrustEngine trustEngine = manager.getTrustEngine();
      Assert.assertNotNull(trustEngine);
      Assert.assertEquals(true, trustEngine.trustEntity(idpMetadata, mockSamlResponseDoc));
      */
    }
    catch(Exception e) {
      fail(e.getMessage());
    }
  }
}
