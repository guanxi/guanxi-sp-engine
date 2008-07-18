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

package org.guanxi.sp.engine;

import org.springframework.web.context.ServletContextAware;
import org.springframework.web.context.support.RequestHandledEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.ContextRefreshedEvent;
import org.apache.log4j.Logger;
import org.guanxi.common.log.Log4JLoggerConfig;
import org.guanxi.common.log.Log4JLogger;
import org.guanxi.common.metadata.IdPMetadataManager;
import org.guanxi.common.metadata.IdPMetadataImpl;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.job.GuanxiJobConfig;
import org.guanxi.common.security.SecUtils;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;

import javax.servlet.ServletContext;
import java.security.Security;
import java.security.Provider;
import java.io.File;
import java.io.FilenameFilter;
import java.text.ParseException;

public class Bootstrap implements ApplicationListener, ApplicationContextAware, ServletContextAware {
  /** Our logger */
  private Logger log = null;
  /** The logger config */
  private Log4JLoggerConfig loggerConfig = null;
  /** The Logging setup to use */
  private Log4JLogger logger = null;
  /** Spring ApplicationContext */
  @SuppressWarnings("unused")
  private ApplicationContext applicationContext = null;
  /** The servlet context */
  private ServletContext servletContext = null;
  /** Holds all the IdP X509 certificates and their chains loaded from the metadata directory. This
   * is what's used to verify an IdP's AuthenticationStatement for example */
  private X509Chain x509Chain = null;
  /** Our configuration */
  private Config config = null;
  /** If this instance of an Engine loads the BouncyCastle security provider then it should unload it */
  private boolean okToUnloadBCProvider = false;
  /** The background jobs to start */
  private GuanxiJobConfig[] gxJobs = null;

  /**
   * Initialise the interceptor
   */
  public void init() {
    try {
      loggerConfig.setClazz(Bootstrap.class);

      // Sort out the file paths for logging
      loggerConfig.setLogConfigFile(servletContext.getRealPath(loggerConfig.getLogConfigFile()));
      loggerConfig.setLogFile(servletContext.getRealPath(loggerConfig.getLogFile()));

      // Get our logger
      log = logger.initLogger(loggerConfig);

      /* If we try to add the BouncyCastle provider but another Guanxi::SP running
       * in another webapp in the same container has already done so, then we'll get
       * -1 returned from the method, in which case, we should leave unloading of the
       * provider to the particular Guanxi::SP that loaded it.
       */
      if ((Security.addProvider(new BouncyCastleProvider())) != -1) {
        // We've loaded it, so we should unload it
        okToUnloadBCProvider = true;
      }

      // If we don't have a keystore, create a self signed one now
      File keyStoreFile = new File(config.getKeystore());
      if (!keyStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createSelfSignedKeystore(config.getId(), // cn
                                            config.getKeystore(),
                                            config.getKeystorePassword(),
                                            config.getKeystorePassword(),
                                            config.getCertificateAlias());
        }
        catch(GuanxiException ge) {
          log.error("Can't create self signed keystore - secure Guard comms won't be available : ", ge);
        }
      }

      // Create a truststore if we don't have one
      File trustStoreFile = new File(config.getTrustStore());
      if (!trustStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createTrustStore(config.getTrustStore(),
                                    config.getTrustStorePassword());
        }
        catch(GuanxiException ge) {
          log.error("Can't create truststore - secure comms won't be available : ", ge);
        }
      }

      loadGuardMetadata(config.getGuardsMetadataDirectory());
      loadIdPMetadata(config.getIdPMetadataDirectory());

      x509Chain = new X509Chain(config.getIdPMetadataDirectory());

      startJobs();
    }
    catch(GuanxiException ge) {
    }
  }

  /**
   * Called by Spring to give us the ApplicationContext
   *
   * @param applicationContext Spring ApplicationContext
   * @throws org.springframework.beans.BeansException
   */
  public void setApplicationContext(ApplicationContext applicationContext) throws org.springframework.beans.BeansException {
    this.applicationContext = applicationContext;
  }

  /**
   * Sets the servlet context
   * @param servletContext The servlet context
   */
  public void setServletContext(ServletContext servletContext) {
    this.servletContext = servletContext;
  }

  /**
   * Called by Spring when application events occur. At the moment we handle:
   * ContextClosedEvent
   * ContextRefreshedEvent
   * RequestHandledEvent
   *
   * This is where we inject the job controllers into the application context, each one
   * under it's own key.
   *
   * @param applicationEvent Spring application event
   */
  public void onApplicationEvent(ApplicationEvent applicationEvent) {
    if (applicationEvent instanceof ContextRefreshedEvent) {
      // Advertise the application as available for business
      servletContext.setAttribute(Guanxi.CONTEXT_ATTR_ENGINE_CONFIG, config);

      // Add the X509 stuff to the context
      servletContext.setAttribute(Guanxi.CONTEXT_ATTR_X509_CHAIN, x509Chain);
      
      log.info("init : " + config.getId());
    }

    if (applicationEvent instanceof ContextClosedEvent) {
      if (okToUnloadBCProvider) {
        Provider[] providers = Security.getProviders();

        /* Although addProvider() returns the ID of the newly installed provider,
         * we can't rely on this. If another webapp removes a provider from the list of
         * installed providers, all the other providers shuffle up the list by one, thus
         * invalidating the ID we got from addProvider().
         */
        try {
          for (int i=0; i < providers.length; i++) {
            if (providers[i].getName().equalsIgnoreCase(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME)) {
              Security.removeProvider(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME);
            }
          }
        }
        catch(SecurityException se) {
          /* We'll end up here if a security manager is installed and it refuses us
           * permission to remove the BouncyCastle provider
           */
        }
      }
    }

    if (applicationEvent instanceof RequestHandledEvent) {
    }
  }

  /**
   * Loads Guard metadata from:
   * WEB-INF/config/metadata/guards
   * If an error occurs the Guard will be ignored.
   *
   * Guard metadata files are in SAML2 format and are named after their containing directory:
   * WEB-INF/config/metadata/guards/protectedapp/protectedapp.xml
   *
   * If a Guard's metadata file is not named after it's containing directory it will be ignored.
   * Normally these directories and metadata files are created by the Engine from the guard request
   * page:
   * /guanxi_sp/request_guard.jsp
   *
   * @param guardsMetadataDir The full path and name of the directory containing the Guard metadata files
   */
  private void loadGuardMetadata(String guardsMetadataDir) {
    File guardsDir = new File(guardsMetadataDir);
    File[] guardFiles = guardsDir.listFiles(new DirFileFilter());

    int loaded = 0;
    for (int count=0; count < guardFiles.length; count++) {
      try {
        // Load up the SAML2 metadata for the Guard
        EntityDescriptorDocument edDoc = EntityDescriptorDocument.Factory.parse(new File(guardFiles[count].getPath() +
                                                                                         File.separator +
                                                                                         guardFiles[count].getName() + ".xml"));
        EntityDescriptorType entityDescriptor = edDoc.getEntityDescriptor();

        // Bung the Guard's SAML2 EntityDescriptor in the context under the Guard's entityID
        servletContext.setAttribute(entityDescriptor.getEntityID(), entityDescriptor);

        loaded++;
      }
      catch(Exception e) {
        // If we get here then the Engine won't know anything about the Guard
        log.error("Error while loading Guard metadata : " +
                  guardFiles[count].getPath() + File.separator + guardFiles[count].getName() + ".xml",
                  e);
      }
    } // for (int count=0; count < guardFiles.length; count++)

    log.info("Loaded " + loaded + " of " + guardFiles.length + " Guard metadata objects");
  } // loadGuardMetadata

  /**
   * Loads IdP metadata from:
   * WEB-INF/config/metadata/idp
   *
   * @param idpMetadataDir The full path and name of the directory containing the IdP metadata files
   * @throws GuanxiException if an error occurs
   */
  private void loadIdPMetadata(String idpMetadataDir) throws GuanxiException {
    File aaDir = new File(idpMetadataDir);
    File[] idpFiles = aaDir.listFiles(new XMLFileFilter());
    
    for ( File current : idpFiles ) {
    	try {
        	EntityDescriptorDocument edDoc;
        	EntityDescriptorType entityDescriptor;
        	
    		edDoc = EntityDescriptorDocument.Factory.parse(current);
    		entityDescriptor = edDoc.getEntityDescriptor();
    		
    		IdPMetadataManager.getManager(servletContext).setMetadata(current.getCanonicalPath(), new IdPMetadataImpl(entityDescriptor));
    	}
    	catch ( Exception e ) {
    		log.error("Error while loading IdP metadata objects", e);
    		throw new GuanxiException(e);
    	}
    }

    log.info("Loaded " + idpFiles.length + " IdP metadata objects");
  } // loadIdPMetadata

  /**
   * Looks for directories during a search
   */
  class DirFileFilter implements FilenameFilter {
    public boolean accept(File file, String name) {
      return file.isDirectory();
    }
  }

  /**
   * Looks for xml files during a search
   */
  class XMLFileFilter implements FilenameFilter {
    public boolean accept(File file, String name) {
      return name.endsWith(".xml");
    }
  }

  private void startJobs() {
    try {
      // Get a new scheduler
      Scheduler scheduler = new StdSchedulerFactory().getScheduler();
      // Start it up. This won't start any jobs though.
      scheduler.start();

      for (GuanxiJobConfig gxJob : gxJobs) {
        log.info("Registering job : " + gxJob.getKey() + " : " + gxJob.getJobClass());

        // Need a new JobDetail to hold custom data to send to the job we're controlling
        JobDetail jobDetail = new JobDetail(gxJob.getKey(), Scheduler.DEFAULT_GROUP, Class.forName(gxJob.getJobClass()));

        // Create a new JobDataMap for custom data to be sent to the job...
        JobDataMap jobDataMap = new JobDataMap();
        // ...and add the job's custom config object
        jobDataMap.put(GuanxiJobConfig.JOB_KEY_JOB_CONFIG, gxJob);

        // Put the job's custom data in it's JobDetail
        jobDetail.setJobDataMap(jobDataMap);

        /* Tell the scheduler when this job will run. Nothing will happen
         * until the start method is called.
         */
        Trigger trigger = new CronTrigger(gxJob.getKey(), Scheduler.DEFAULT_GROUP, gxJob.getCronLine());

        // Start the job
        scheduler.scheduleJob(jobDetail, trigger);

        if (gxJob.isStartImmediately()) {
          scheduler.triggerJob(gxJob.getKey(), Scheduler.DEFAULT_GROUP);
        }
      }
    }
    catch(ClassNotFoundException cnfe) {
      log.error("Error locating job class", cnfe);
    }
    catch(SchedulerException se) {
      log.error("Job scheduling error", se);
    }
    catch(ParseException pe) {
      log.error("Error parsing job cronline", pe);
    }
  }

  public void setLoggerConfig(Log4JLoggerConfig loggerConfig) { this.loggerConfig = loggerConfig; }
  public Log4JLoggerConfig getLoggerConfig() { return loggerConfig; }

  public void setLogger(Log4JLogger logger) { this.logger = logger; }
  public Log4JLogger getLogger() { return logger; }


  public void setConfig(Config config) { this.config = config; }
  public Config getConfig() { return config; }

  public void setGxJobs(GuanxiJobConfig[] gxJobs) { this.gxJobs = gxJobs; }
}
