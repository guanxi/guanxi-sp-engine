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

package org.guanxi.sp.engine.trust.impl;

import org.guanxi.common.trust.impl.SimpleTrustEngine;
import org.guanxi.common.metadata.Metadata;

import java.util.Vector;
import java.security.cert.X509Certificate;

/**
 * TrustManager implementation that the Engine uses to trust Guards via their local metadata
 *
 * @author alistair
 */
public class GuanxiLocalTrustEngineImpl extends SimpleTrustEngine {
  private Vector<X509Certificate> caCerts = null;

  public GuanxiLocalTrustEngineImpl() {
    super();
  }

  /** @see org.guanxi.common.trust.TrustEngine#trustEntity(org.guanxi.common.metadata.Metadata, Object) */
  public boolean trustEntity(Metadata entityMetadata, Object entityData) {
    //@todo default implementation - change
    return true;
  }
}
