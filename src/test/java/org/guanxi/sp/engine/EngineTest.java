/* CVS Header
   $
   $
*/

package org.guanxi.sp.engine;

import org.springframework.mock.web.MockServletContext;
import org.junit.BeforeClass;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

public abstract class EngineTest {
  protected static MockServletContext servletContext = null;
  protected static String engineHome = null;
  protected static String[] metadataConfigFiles = null;


  @BeforeClass
  public static void initEngineTest() {
    try {
      engineHome = "file:///" + new File(".").getCanonicalPath() + "/src/main/webapp";
    }
    catch(IOException ioe) {
      fail(ioe.getMessage());
    }

    metadataConfigFiles = new String[] {engineHome + "/WEB-INF/guanxi_sp_engine/config/spring/application/jobs/ukFederationMetadataParser.xml",
                                        engineHome + "/WEB-INF/guanxi_sp_engine/config/spring/application/entity.xml"};
    
    servletContext = new MockServletContext(engineHome);
  }
}
