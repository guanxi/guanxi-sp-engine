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

package org.guanxi.sp.engine.service.generic;

import org.guanxi.common.GuanxiException;
import org.guanxi.common.entity.EntityFarm;
import org.guanxi.xal.saml2.metadata.GuardRoleDescriptorExtensions;
import org.springframework.web.servlet.ModelAndView;

/**
 * Profile service defintion
 *
 * @author alistair
 */
public interface ProfileService {
  /**
   * Initialise the profile service
   */
  public void init();

  /**
   * Performs the work of constructing a route to an entity using a particular profile
   *
   * @param guardID the ID of the Guard which wants to talk to the entity
   * @param guardSessionID the sessionid of the Guard which wants to talk to the entity
   * @param guardNativeMetadata the metadata of the Guard which wants to talk to the entity
   * @param entityID the ID of the entity or null if it isn't known
   * @param farm the entity farm to use
   * @return ModelAndView that is ready to be used to communicate with the entity
   * @throws GuanxiException if an error occurs
   */
  public ModelAndView doProfile(String guardID, String guardSessionID, GuardRoleDescriptorExtensions guardNativeMetadata,
                                String entityID, EntityFarm farm) throws GuanxiException;
}
