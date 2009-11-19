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

package org.guanxi.sp;

import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.guanxi.xal.saml2.metadata.GuanxiGuardServiceDocument;
import org.guanxi.xal.saml_2_0.metadata.EntityDescriptorType;
import org.guanxi.xal.saml_2_0.metadata.RoleDescriptorType;
import org.guanxi.xal.saml_2_0.metadata.ExtensionsType;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.apache.xmlbeans.XmlException;

/**
 * Guanxi Service Provider utility class
 * 
 * @author Alistair Young
 */
public class Util {
  /**
   * Extracts Guard native metadata from a SAML2 EntityDescriptor
   *
   * @param saml2Metadata SAML2 EntityDescriptor
   * @return GuanxiGuardService node from the SAML2 EntityDescriptor
   */
  public static GuardRoleDescriptorExtensions getGuardNativeMetadata(EntityDescriptorType saml2Metadata) {
    RoleDescriptorType roleDescriptor = saml2Metadata.getRoleDescriptorArray()[0];
    ExtensionsType et = roleDescriptor.getExtensions();
    NodeList nodes = et.getDomNode().getChildNodes();
    Node extChildNode = null;
    for (int c=0; c < nodes.getLength(); c++) {
      extChildNode = nodes.item(c);
      if (extChildNode.getLocalName() != null) {
        if (extChildNode.getLocalName().equals("GuanxiGuardService")) break;
      }
    }
    try {
      return GuanxiGuardServiceDocument.Factory.parse(extChildNode).getGuanxiGuardService();
    }
    catch(XmlException xe) {
      return null;
    }
  }

  /**
   * Determines whether a Guard is using HTTPS for any of it's endpoints
   *
   * @param guardExt GuanxiGuardService node from the SAML2 EntityDescriptor
   * @return true if the Guard is using HTTPS for any of it's endpoints otherwise false
   */
  public static boolean isGuardSecure(GuardRoleDescriptorExtensions guardExt) {
    return guardExt.getVerifierURL().toLowerCase().startsWith("https")                 ||
           guardExt.getAttributeConsumerServiceURL().toLowerCase().startsWith("https");
           //guardExt.getPodderURL().toLowerCase().startsWith("https"); 
  }

  /**
   * Determines whether an Attribute Authority is using HTTPS for any of it's endpoints
   *
   * @param idPMetadata EntityDescriptorType node from the SAML2 EntityDescriptor
   * @return true if the AA is using HTTPS for any of it's endpoints otherwise false
   */
  public static boolean isAASecure(EntityDescriptorType idPMetadata) {
    return idPMetadata.getAttributeAuthorityDescriptorArray()[0].getAttributeServiceArray()[0].getLocation().startsWith("https");
  }
}
