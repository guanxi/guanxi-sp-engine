/* CVS Header
   $
   $
*/

package org.guanxi.sp.engine;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.guanxi.sp.engine.trust.TrustTestSuite;

/**
 * This is the root of all tests. It will invoke the various test suites that handle
 * testing of the various Engine subsystems.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses( { TrustTestSuite.class} )
public class EngineTestSuite {
}
