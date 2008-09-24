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

package org.guanxi.sp.engine.job.hibernate;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.axis.encoding.Base64;
import org.apache.log4j.Logger;
import org.guanxi.common.job.GuanxiJobConfig;
import org.guanxi.common.job.SimpleGuanxiJobConfig;
import org.guanxi.common.metadata.IdPMetadata;
import org.guanxi.common.metadata.IdPMetadataImpl;
import org.guanxi.common.metadata.IdPMetadataManager;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

public class MetadataLoader implements Job {
  /**
   * This is the logger used by this class.
   */
  private static final Logger logger      = Logger.getLogger(MetadataLoader.class.getName());
  
  /**
   * This is the string that marks the beginning of a PEM encoded certificate
   */
  private static final String pemPrefix   = "-----BEGIN CERTIFICATE-----";
  /**
   * This is the string that marks the end of a PEM encoded certificate
   */
  private static final String pemPostfix  = "-----END CERTIFICATE-----";
  /**
   * This is the Pattern object that can be used to match the content of PEM
   * encoded certificates. Group #1 will contain the base64 encoded certificate.
   */
  private static final Pattern pemPattern = Pattern.compile(pemPrefix + "(.*)" + pemPostfix, Pattern.DOTALL);
  /**
   * This is the string that will be used to represent the source of the metadata.
   * This indicates that hibernate has been used to load the data from the database.
   * If this class is expanded to support multiple databases then this may have to
   * become a class variable.
   */
  private static final String metadataSource = "hibernate";
  /**
   * This is the session factory which creates sessions which can be used
   * to access or update the database.
   */
  private static SessionFactory sessionFactory;
  
  /**
   * This initialises the SessionFactory so that the database can be accessed.
   * This is separate from the constructor because the SessionFactory is static
   * and intended to be shared amongst jobs.
   */
  private static void init() {
    if ( sessionFactory != null ) {
      return;
    }
    try {
      // Create the SessionFactory from hibernate.cfg.xml
      sessionFactory = new Configuration().configure("/org/guanxi/sp/engine/job/hibernate/hibernate.cfg.xml").buildSessionFactory();
    }
    catch (Throwable e) {
      // Make sure you log the exception, as it might be swallowed
      logger.error("Initial SessionFactory creation failed.", e);
      throw new ExceptionInInitializerError(e);
    }
  }
  
  public MetadataLoader() {
    init();
  }

  /**
   * This job loads all of the available data from the database,
   * removing the previous load. If the data in the database is
   * malformed then no change to the loaded metadata is made.
   * 
   * @param context   The context contains a reference to the configuration which controls some aspects of this job.
   */
  public void execute(JobExecutionContext context) throws JobExecutionException {
    MetadataLoaderConfig config;
    IdPMetadataManager   manager;
    Logger               logger;
    List<IdPMetadataDAO> idpList;

    config  = (MetadataLoaderConfig) context.getJobDetail().getJobDataMap().get(GuanxiJobConfig.JOB_KEY_JOB_CONFIG);
    logger  = SimpleGuanxiJobConfig.createLogger(config.getServletContext().getRealPath(config.getLoggerConfigurationFile()), MetadataLoader.class.getName());
    
    logger.info("Loading metadata from the database");
    try {
      manager = IdPMetadataManager.getManager();
      idpList = load();
      manager.setMetadata(metadataSource, convert(idpList));
    }
    catch ( Exception e ) {
      logger.error("Unable to load metadata from database", e);
      throw new JobExecutionException(e);
    }
    logger.info("Loading metadata from database completed successfully");
  }
  
  /**
   * This converts the metadata from the database format into a format supported
   * by the MetadataManager. If there is a problem converting the certificates into
   * the required format then an exception will be thrown. When that happens you must
   * check the certificates in the database to ensure they are valid.
   * 
   * @param hibernateList
   * @return
   * @throws IllegalArgumentException
   * @throws Base64DecodingException
   */
  private static IdPMetadata[] convert(List<IdPMetadataDAO> hibernateList) throws IllegalArgumentException, Base64DecodingException {
    List<IdPMetadata> result;
    
    result = new ArrayList<IdPMetadata>();
    for ( IdPMetadataDAO current : hibernateList ) {
      result.add(new IdPMetadataImpl(current.getEntityID(), current.getAttributeAuthorityURL(), pemToX509(current.getPemCertificate())));
    }
    
    return result.toArray(new IdPMetadata[result.size()]);
  }
  
  /**
   * This loads all of the metadata available from the database.
   * 
   * @return  A list of all of the metadata that was loaded.
   */
  @SuppressWarnings("unchecked")
  private static List<IdPMetadataDAO> load() {
    Session              session;
    List<IdPMetadataDAO> idpList;

    session = sessionFactory.getCurrentSession();
    session.beginTransaction();
    
    idpList = session.createQuery("from IdPMetadataDAO").list();
    
    session.getTransaction().commit();
    
    return idpList;
  }
  
  /**
   * This converts a x509Certificate into PEM format. This utility
   * method is currently unused because data is not currently inserted
   * into the database programmatically, however if that happens then
   * this will become useful.
   * 
   * @param x509Certificate The certificate data to convert.
   * @return                The certificate in PEM format.
   */
  private static String x509ToPEM(byte[] x509Certificate) {
    StringBuilder result;
    
    result = new StringBuilder(pemPrefix);
    result.append(Base64.encode(x509Certificate));
    result.append(pemPostfix);
    
    return result.toString();
  }
  
  /**
   * This converts a PEM certificate into x509 format.
   * 
   * @param pemCertificate            The certificate data to convert.
   * @return                          The certificate in x509 format.
   * @throws IllegalArgumentException If the certificate does not have the PEM prefix and postfix.
   * @throws Base64DecodingException  If the content of the certificate cannot be decoded as base64.
   */
  private static byte[] pemToX509(String pemCertificate) throws IllegalArgumentException {
    Matcher matcher;
    
    matcher = pemPattern.matcher(pemCertificate);
    if ( !matcher.find() ) {
      throw new IllegalArgumentException("String passed in does not match the format of a PEM encoded certificate\n" + pemCertificate);
    }
    
    return Base64.decode(matcher.group(1));
  }
}
