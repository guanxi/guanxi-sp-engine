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

package org.guanxi.sp.engine.service.saml2;

import java.util.Hashtable;

/**
 * Encapsulates information about an entity for the Embedded Discovery Service to display
 *
 * @author alistair
 */
public class DiscoveryEntity {
  private String entityID = null;
  private Hashtable<String, String> displayNames;

  public DiscoveryEntity(String entityID) {
    this.entityID = entityID;
    displayNames = new Hashtable<String, String>();
  }

  public void addDisplayName(String displayName, String language) {
    displayNames.put(displayName, language);
  }

  public Hashtable<String, String> getDisplayNames() {
    return displayNames;
  }
}
