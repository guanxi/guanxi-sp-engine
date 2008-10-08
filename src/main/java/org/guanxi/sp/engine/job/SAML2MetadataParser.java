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
import org.apache.xmlbeans.XmlException;
import org.guanxi.xal.saml_2_0.metadata.EntitiesDescriptorDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.metadata.ExtensionsType;
import org.guanxi.xal.shibboleth_1_0.metadata.KeyAuthorityDocument;
import org.guanxi.xal.w3.xmldsig.KeyInfoType;
import org.guanxi.xal.w3.xmldsig.X509DataType;
import org.guanxi.common.Utils;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.entity.EntityManager;
import org.guanxi.common.metadata.Metadata;
import org.guanxi.common.job.SAML2MetadataParserConfig;
import org.guanxi.common.job.GuanxiJobConfig;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;

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

    EntityFarm farm = (EntityFarm)config.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_ENGINE_ENTITY_FARM);
    EntityManager manager = farm.getEntityManagerForSource(config.getMetadataURL());
    manager.removeMetadata();

    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("x.509");
      ExtensionsType extensions = doc.getEntitiesDescriptor().getExtensions();

      /* Find the shibmeta:KeyAuthority node. This lists all the root CAs
       * that we trust.
       */
      Node keyAuthorityNode = null;
      NodeList nodes = extensions.getDomNode().getChildNodes();
      for (int c=0; c < nodes.getLength(); c++) {
        if (nodes.item(c).getLocalName() != null) {
          if (nodes.item(c).getLocalName().equals("KeyAuthority")) {
            keyAuthorityNode = nodes.item(c);
          }
        }
      }

      // Load all the root CAs into the trust engine
      if (keyAuthorityNode != null) {
        KeyAuthorityDocument keyAuthDoc = KeyAuthorityDocument.Factory.parse(keyAuthorityNode);
        KeyInfoType[] keyInfos = keyAuthDoc.getKeyAuthority().getKeyInfoArray();
        for (KeyInfoType keyInfo : keyInfos) {
          X509DataType[] x509Datas = keyInfo.getX509DataArray();
          for (X509DataType x509Data : x509Datas) {
            byte[][] x509Certs = x509Data.getX509CertificateArray();
            for (byte[] x509CertBytes : x509Certs) {
              ByteArrayInputStream certByteStream = new ByteArrayInputStream(x509CertBytes);
              manager.getTrustEngine().addCACert((X509Certificate)certFactory.generateCertificate(certByteStream));
              certByteStream.close();
            }
          }
        }
      }
      else {
        logger.error("Could not find shibmeta:KeyAuthority in metadata");
      }

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
    catch(CertificateException ce) {
      logger.error("Could not prepare certificate factory", ce);
    }
    catch(IOException ioe) {
      logger.error("Could not close byte stream", ioe);
    }
    catch(XmlException xe) {
      logger.error("Could not load shibboleth extensions from metadata", xe);
    }
    catch(GuanxiException ge) {
      logger.error("Could not get an entity handler from the metadata manager", ge);
    }
  }
}
