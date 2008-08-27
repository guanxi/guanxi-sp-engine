/**
 * 
 */
package org.guanxi.sp.engine.job.hibernate;

import org.guanxi.common.job.SimpleGuanxiJobConfig;

/**
 * @author matthew
 *
 */
public class MetadataLoaderConfig extends SimpleGuanxiJobConfig {
  
  private boolean startImmediately;

  /**
   * @return the startImmediately
   */
  public boolean isStartImmediately() {
    return startImmediately;
  }

  /**
   * @param startImmediately the startImmediately to set
   */
  public void setStartImmediately(boolean startImmediately) {
    this.startImmediately = startImmediately;
  }
}
