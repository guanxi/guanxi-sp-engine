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

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Manages the entities to be displayed by the Embedded Discovery Service (EDS)
 *
 * @author alistair
 */
public class DiscoveryFeedManager {
  private Hashtable<String, DiscoveryEntity> entities = null;
  public void init() {
    entities = new Hashtable<String, DiscoveryEntity>();
  }

  public void destroy() {}

  /**
   * Adds an entity to the EDS
   *
   * @param entityID the entity's entityID from its metadata
   */
  public void addEntity(String entityID) {
    if (!entities.containsKey(entityID)) {
      entities.put(entityID, new DiscoveryEntity(entityID));
    }
  }

  /**
   * Deletes an entity from the EDS
   *
   * @param entityID the entity's entityID from its metadata
   */
  public void deleteEntity(String entityID) {
    if (entities.containsKey(entityID)) {
      entities.remove(entityID);
    }
  }

  /**
   * Adds a display name to the entity
   *
   * @param entityID the entity's entityID from its metadata
   * @param displayName the display name for the EDS
   * @param language the two letter language code for this display name
   */
  public void addDisplayName(String entityID, String displayName, String language) {
    if (entities.containsKey(entityID)) {
      ((DiscoveryEntity)(entities.get(entityID))).addDisplayName(displayName, language);
    }
  }

  /**
   * Returns a JSON representation for the EDS to display
   *
   * @see {@linktourl }https://spaces.internet2.edu/download/attachments/11075654/json_schema.json?version=1&modificationDate=1289903420875}
   * @return JSON representing all registered entities
   */
  public String toJSON() {
    String json = "[";

    String entityID = null;
    DiscoveryEntity entity = null;
    Enumeration<String> entityIDs = entities.keys();
    while (entityIDs.hasMoreElements()) {
      entityID = (String)entityIDs.nextElement();
      entity = entities.get(entityID);

      json += "{";
      json += "\"entityID\": \"" + entityID + "\",";

      String displayName, displayNameLang = null;
      Enumeration<String> displayNames = entity.getDisplayNames().keys();
      json += "\"DisplayNames\": [";
      while (displayNames.hasMoreElements()) {
        json += "{";
        displayName = (String)displayNames.nextElement();
        displayNameLang = entity.getDisplayNames().get(displayName);
        json += "\"value\": \"" + displayName + "\",";
        json += "\"lang\": \"" + displayNameLang + "\"";
        json += "}";
        if (displayNames.hasMoreElements()) json += ",";
      }
      json += "]";
      json += "}";
      if (entityIDs.hasMoreElements()) json += ",";
    }

    json += "]";

    return json;
  }
}
