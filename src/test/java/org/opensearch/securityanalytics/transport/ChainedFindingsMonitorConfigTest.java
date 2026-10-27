/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.test.OpenSearchTestCase;

public class ChainedFindingsMonitorConfigTest extends OpenSearchTestCase {

    /**
     * Pins the public constant introduced in TransportIndexDetectorAction to {@code false}.
     * The production {@code createDocLevelMonitorMatchAllRequest} method now references
     * {@code CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN} directly, so this test
     * will fail if the constant is changed to {@code true} — catching a regression without
     * requiring full class instantiation.
     */
    public void testChainedFindingsMonitorConstant_deleteQueryIndexInEveryRun_isFalse() {
        assertFalse(
                "CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN must be false to prevent the " +
                "chained_findings monitor from deleting its query index on every execution cycle " +
                "(regression #1725). Do not change this constant without understanding the " +
                "DocLevelMonitorQueries.kt interaction in opensearch-project/alerting.",
                TransportIndexDetectorAction.CHAINED_FINDINGS_DELETE_QUERY_INDEX_IN_EVERY_RUN
        );
    }

    /**
     * Validates the Monitor constructor API contract: the {@code deleteQueryIndexInEveryRun}
     * argument is stored and returned by the getter.
     *
     * <p><b>Known limitation:</b> This test constructs a {@code Monitor} directly and does
     * NOT call {@code createDocLevelMonitorMatchAllRequest}. The stronger regression
     * guarantee comes from {@link #testChainedFindingsMonitorConstant_deleteQueryIndexInEveryRun_isFalse},
     * which pins the constant that the production method now reads at the call site.
     */
    public void testChainedFindingsMonitor_deleteQueryIndexInEveryRun_isFalse() {
        boolean deleteQueryIndexInEveryRun = false;

        Monitor monitor = new Monitor(
                "test_monitor_id",
                -3L,
                "test_detector_chained_findings",
                false,
                new CronSchedule("0 * * * *", ZoneId.of("UTC"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                null,
                1,
                List.of(),
                List.of(),
                Map.of(),
                new DataSources(),
                deleteQueryIndexInEveryRun,
                null,
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                null,
                null
        );

        assertEquals(
                "chained_findings monitor must have deleteQueryIndexInEveryRun=false to prevent " +
                    "the query index from being wiped on every execution cycle (regression #1725)",
                Boolean.FALSE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
    }

    /**
     * Adversarial sanity check: when {@code deleteQueryIndexInEveryRun=true} is passed,
     * the monitor reflects that value. Confirms the regression assertion above is
     * non-trivial — the getter does not ignore the constructor argument.
     */
    public void testMonitor_deleteQueryIndexInEveryRun_reflectsConstructorArg_whenTrue() {
        Monitor monitor = new Monitor(
                "test_monitor_id",
                -3L,
                "test_detector_chained_findings",
                false,
                new CronSchedule("0 * * * *", ZoneId.of("UTC"), Instant.ofEpochSecond(1538164858L)),
                Instant.now(),
                null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                null,
                1,
                List.of(),
                List.of(),
                Map.of(),
                new DataSources(),
                true, // intentionally the pre-fix (buggy) value
                null,
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD,
                null,
                null
        );

        assertEquals(
                "Monitor with deleteQueryIndexInEveryRun=true must expose that value via getter; " +
                    "confirms the regression assertion in the sibling test is meaningful",
                Boolean.TRUE,
                monitor.getDeleteQueryIndexInEveryRun()
        );
    }

    /**
     * PLUGIN_OWNER_FIELD must equal the sentinel value the alerting plugin uses
     * to identify monitors owned by security-analytics.
     */
    public void testPluginOwnerField_hasExpectedValue() {
        assertEquals(
                "PLUGIN_OWNER_FIELD must identify this plugin to the alerting subsystem",
                "security_analytics",
                TransportIndexDetectorAction.PLUGIN_OWNER_FIELD
        );
    }
}
